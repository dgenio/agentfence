package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"sort"
	"strings"
	"syscall"

	"github.com/dgenio/agentfence/internal/audit"
	"github.com/dgenio/agentfence/internal/demo"
	"github.com/dgenio/agentfence/internal/engine"
	"github.com/dgenio/agentfence/internal/policy"
	"github.com/dgenio/agentfence/internal/proxy"
)

// Version is the current release version. Override at build time with:
//
//	go build -ldflags "-X main.Version=0.1.0" ./cmd/agentfence
var Version = "dev"

// DecisionSummary is the JSON-serialisable shape written for --output json/jsonl.
type DecisionSummary struct {
	ID       string          `json:"id"`
	Tool     string          `json:"tool"`
	Decision policy.Decision `json:"decision"`
	Reason   string          `json:"reason"`
}

func main() {
	// Handle --version / -version before the subcommand switch so it works
	// regardless of argument position.
	for _, arg := range os.Args[1:] {
		if arg == "--version" || arg == "-version" {
			runVersion()
			return
		}
	}

	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	var err error
	switch os.Args[1] {
	case "audit":
		err = runAuditSubcmd(os.Args[2:])
	case "check":
		err = runCheck(os.Args[2:])
	case "demo":
		err = demo.Run(os.Stdout)
	case "explain":
		err = runExplain(os.Args[2:])
	case "init":
		err = runInit()
	case "policy":
		err = runPolicySubcmd(os.Args[2:])
	case "proxy":
		err = runProxy(os.Args[2:])
	case "validate":
		err = runValidate(os.Args[2:])
	case "version":
		runVersion()
	default:
		printUsage()
		err = fmt.Errorf("unknown command: %s", os.Args[1])
	}

	if err != nil {
		// Subprocess exit propagation: the proxy returns *exec.ExitError when
		// the downstream MCP server exits non-zero. We surface that exit code
		// verbatim so wrappers can distinguish "policy proxy failed" from
		// "the MCP server itself errored" without parsing stderr. We only
		// reach this branch after every defer (including audit-log close) has
		// run.
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			os.Exit(exitErr.ExitCode())
		}
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func runVersion() {
	fmt.Printf("agentfence %s %s/%s\n", Version, runtime.GOOS, runtime.GOARCH)
}

func runCheck(args []string) error {
	fs := flag.NewFlagSet("check", flag.ContinueOnError)
	policyPath := fs.String("policy", "", "Path to policy YAML")
	callPath := fs.String("call", "", "Path to JSONL tool-call input")
	auditLogPath := fs.String("audit-log", "", "Optional path to write audit JSONL")
	outputMode := fs.String("output", "text", "Output mode: text, json, jsonl")
	failOn := fs.String("fail-on", "", "Comma-separated decisions to fail on: deny, ask")
	tamperEvident := fs.Bool("tamper-evident", false, "Write a hash-chained audit log (use with --audit-log; verify with 'agentfence audit verify')")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *policyPath == "" || *callPath == "" {
		return errors.New("--policy and --call are required")
	}

	switch *outputMode {
	case "text", "json", "jsonl":
	default:
		return fmt.Errorf("unknown --output mode %q; valid values: text, json, jsonl", *outputMode)
	}

	// Parse and validate --fail-on before opening files.
	failOnSet := map[policy.Decision]bool{}
	if *failOn != "" {
		for _, raw := range strings.Split(*failOn, ",") {
			d := policy.Decision(strings.TrimSpace(raw))
			switch d {
			case policy.DecisionDeny, policy.DecisionAsk:
				failOnSet[d] = true
			case policy.DecisionAllow:
				return fmt.Errorf("--fail-on allow is not a valid gate value; use deny or ask")
			default:
				return fmt.Errorf("--fail-on: unknown decision %q; valid values: deny, ask", raw)
			}
		}
	}

	p, err := policy.LoadFile(*policyPath)
	if err != nil {
		return err
	}

	eng, err := engine.New(p)
	if err != nil {
		return err
	}

	// Audit output: use the explicit file when given; for structured output modes
	// default to discarding (mixing audit JSONL into a JSON stream breaks parsers);
	// for text mode preserve the existing behaviour of writing to stdout.
	var auditOut io.Writer = io.Discard
	if *auditLogPath != "" {
		f, err := os.Create(*auditLogPath)
		if err != nil {
			return err
		}
		defer f.Close()
		auditOut = f
	} else if *outputMode == "text" {
		auditOut = os.Stdout
	}

	if *tamperEvident && *auditLogPath == "" {
		fmt.Fprintln(os.Stderr, "AgentFence: warning: --tamper-evident without --audit-log produces a chain interleaved with other output; verification will not be reliable.")
	}

	aw := audit.NewWriterOptions(auditOut, audit.Options{TamperEvident: *tamperEvident})

	callsFile, err := os.Open(*callPath)
	if err != nil {
		return err
	}
	defer callsFile.Close()

	scanner := bufio.NewScanner(callsFile)
	lineNum := 0
	parseErrors := 0
	counts := map[policy.Decision]int{}
	summaries := make([]DecisionSummary, 0)

	for scanner.Scan() {
		lineNum++
		call, err := policy.ParseToolCall(scanner.Bytes())
		if err != nil {
			parseErrors++
			callID := fmt.Sprintf("line-%d", lineNum)
			reason := fmt.Sprintf("parse error: %s", err)
			_ = aw.Write(audit.NewErrorEvent(lineNum, err.Error()))
			summary := DecisionSummary{
				ID:       callID,
				Tool:     "",
				Decision: policy.DecisionDeny,
				Reason:   reason,
			}
			switch *outputMode {
			case "text":
				fmt.Printf("%s  -> deny (%s)\n", callID, reason)
			case "jsonl":
				b, err := json.Marshal(summary)
				if err != nil {
					return fmt.Errorf("marshal summary: %w", err)
				}
				fmt.Printf("%s\n", b)
			case "json":
				summaries = append(summaries, summary)
			}
			counts[policy.DecisionDeny]++
			continue
		}

		res, event := eng.Evaluate(call)
		summary := DecisionSummary{
			ID:       call.ID,
			Tool:     call.Tool,
			Decision: res.Decision,
			Reason:   res.Reason,
		}

		switch *outputMode {
		case "text":
			fmt.Printf("%s %s -> %s (%s)\n", call.ID, call.Tool, res.Decision, res.Reason)
		case "jsonl":
			b, err := json.Marshal(summary)
			if err != nil {
				return fmt.Errorf("marshal summary: %w", err)
			}
			fmt.Printf("%s\n", b)
		case "json":
			summaries = append(summaries, summary)
		}

		counts[res.Decision]++
		if err := aw.Write(event); err != nil {
			return err
		}
	}

	if err := scanner.Err(); err != nil {
		return err
	}

	if *outputMode == "json" {
		b, err := json.Marshal(summaries)
		if err != nil {
			return err
		}
		fmt.Printf("%s\n", b)
	}

	if *outputMode == "text" && lineNum > 0 {
		fmt.Printf("\n%d call(s) processed, %d parse error(s): allow=%d deny=%d ask=%d\n",
			lineNum, parseErrors,
			counts[policy.DecisionAllow], counts[policy.DecisionDeny], counts[policy.DecisionAsk])
	}

	if lineNum > 0 && lineNum == parseErrors {
		return fmt.Errorf("all %d line(s) failed to parse; no calls were evaluated", lineNum)
	}

	// --fail-on: exit 1 if any call matched a gated decision.
	if len(failOnSet) > 0 {
		matched := 0
		for d := range failOnSet {
			matched += counts[d]
		}
		if matched > 0 {
			gated := make([]string, 0, len(failOnSet))
			for d := range failOnSet {
				gated = append(gated, string(d))
			}
			sort.Strings(gated)
			fmt.Fprintf(os.Stderr, "AgentFence: %d call(s) matched --fail-on criteria (%s)\n", matched, strings.Join(gated, ", "))
			return fmt.Errorf("%d call(s) matched --fail-on criteria", matched)
		}
	}

	return nil
}

func runValidate(args []string) error {
	fs := flag.NewFlagSet("validate", flag.ContinueOnError)
	policyPath := fs.String("policy", "", "Path to policy YAML")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *policyPath == "" {
		return errors.New("--policy is required")
	}

	b, err := os.ReadFile(*policyPath)
	if err != nil {
		return err
	}

	errs := policy.ValidateStrict(b)
	if len(errs) == 0 {
		fmt.Printf("%s: OK\n", *policyPath)
		return nil
	}

	for _, e := range errs {
		if e.Field == "" {
			fmt.Fprintf(os.Stderr, "%s: %s\n", *policyPath, e.Message)
		} else {
			fmt.Fprintf(os.Stderr, "%s: %s: %s\n", *policyPath, e.Field, e.Message)
		}
	}
	return fmt.Errorf("%s: %d validation error(s)", *policyPath, len(errs))
}

func runInit() error {
	const fileName = "agentfence.yaml"
	if _, err := os.Stat(fileName); err == nil {
		return fmt.Errorf("%s already exists", fileName)
	}
	if err := os.WriteFile(fileName, []byte(policy.StarterPolicyYAML), 0o644); err != nil {
		return err
	}
	fmt.Printf("Created %s\n", fileName)
	return nil
}

func printUsage() {
	fmt.Println("Usage:")
	fmt.Println("  agentfence check   --policy <file> --call <jsonl> [--audit-log <file>] [--output text|json|jsonl] [--fail-on deny|ask|deny,ask] [--tamper-evident]")
	fmt.Println("  agentfence explain --policy <file> --tool <name> [--args <json>] [--output text|json]")
	fmt.Println("  agentfence policy  test     --policy <file> --tests <yaml> [--verbose]")
	fmt.Println("  agentfence policy  validate --policy <file>")
	fmt.Println("  agentfence proxy   --policy <file> [--audit-log <file>] [--tamper-evident] [--passthrough] [--no-interactive] [--debug] -- <command> [args...]")
	fmt.Println("  agentfence validate --policy <file>")
	fmt.Println("  agentfence audit   verify   --log <file>")
	fmt.Println("  agentfence version")
	fmt.Println("  agentfence demo")
	fmt.Println("  agentfence init")
}

// runExplain evaluates a single tool call and prints a human-readable decision trace.
func runExplain(args []string) error {
	fs := flag.NewFlagSet("explain", flag.ContinueOnError)
	policyPath := fs.String("policy", "", "Path to policy YAML")
	toolName := fs.String("tool", "", "Tool name to explain (e.g. filesystem.write)")
	argsStr := fs.String("args", "{}", "JSON object of tool call arguments")
	outputMode := fs.String("output", "text", "Output mode: text, json")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *policyPath == "" {
		return errors.New("--policy is required")
	}
	if *toolName == "" {
		return errors.New("--tool is required")
	}

	p, err := policy.LoadFile(*policyPath)
	if err != nil {
		return err
	}
	eng, err := engine.New(p)
	if err != nil {
		return err
	}

	var arguments map[string]interface{}
	if err := json.Unmarshal([]byte(*argsStr), &arguments); err != nil {
		return fmt.Errorf("--args: invalid JSON: %w", err)
	}
	if arguments == nil {
		return fmt.Errorf("--args: must be a JSON object, got null")
	}

	call := policy.ToolCall{
		ID:        "explain",
		Tool:      *toolName,
		Arguments: arguments,
	}

	result, trace := eng.TraceEvaluate(call)

	switch *outputMode {
	case "json":
		out := struct {
			Decision string   `json:"decision"`
			Reason   string   `json:"reason"`
			Trace    []string `json:"trace"`
		}{
			Decision: string(result.Decision),
			Reason:   result.Reason,
			Trace:    trace,
		}
		b, err := json.MarshalIndent(out, "", "  ")
		if err != nil {
			return fmt.Errorf("explain: json marshal: %w", err)
		}
		fmt.Printf("%s\n", b)
	case "text":
		fmt.Printf("tool:     %s\n", *toolName)
		fmt.Printf("decision: %s\n", result.Decision)
		fmt.Printf("reason:   %s\n", result.Reason)
		if len(trace) > 0 {
			fmt.Printf("trace:\n")
			for _, step := range trace {
				fmt.Printf("  - %s\n", step)
			}
		}
	default:
		return fmt.Errorf("--output: unknown mode %q; valid values: text, json", *outputMode)
	}
	return nil
}

// runAuditSubcmd dispatches audit sub-commands: verify.
func runAuditSubcmd(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("audit requires a subcommand: verify")
	}
	switch args[0] {
	case "verify":
		return runAuditVerify(args[1:])
	default:
		return fmt.Errorf("unknown audit subcommand %q; valid: verify", args[0])
	}
}

// runAuditVerify checks the tamper-evident hash chain of a JSONL audit log.
func runAuditVerify(args []string) error {
	fs := flag.NewFlagSet("audit verify", flag.ContinueOnError)
	logPath := fs.String("log", "", "Path to audit JSONL log to verify")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *logPath == "" {
		return errors.New("--log is required")
	}

	f, err := os.Open(*logPath)
	if err != nil {
		return err
	}
	defer f.Close()

	n, err := audit.VerifyChain(f)
	switch {
	case err == nil:
		fmt.Printf("OK: %d event(s) verified\n", n)
		return nil
	case errors.Is(err, audit.ErrNoChain):
		fmt.Fprintf(os.Stderr, "AgentFence: warning: %s; cannot verify integrity\n", err)
		fmt.Printf("PARSED: %d event(s); chain absent\n", n)
		return nil
	default:
		var ve *audit.VerifyError
		if errors.As(err, &ve) {
			return fmt.Errorf("audit verify: %s", ve.Error())
		}
		return fmt.Errorf("audit verify: %w", err)
	}
}

// runProxy launches the MCP stdio proxy. The downstream MCP server command
// is supplied as positional arguments after `--`:
//
//	agentfence proxy --policy policy.yaml -- node my-mcp-server.js --foo
//
// The proxy spawns the command, relays JSON-RPC messages in both directions,
// and intercepts tools/call requests for policy evaluation. See
// docs/integration-guide.md for end-to-end configuration examples.
func runProxy(args []string) error {
	fs := flag.NewFlagSet("proxy", flag.ContinueOnError)
	policyPath := fs.String("policy", "", "Path to policy YAML (required unless --passthrough)")
	auditLogPath := fs.String("audit-log", "", "Optional path to write audit JSONL")
	tamperEvident := fs.Bool("tamper-evident", false, "Write a hash-chained audit log (use with --audit-log; verify with 'agentfence audit verify')")
	passthrough := fs.Bool("passthrough", false, "Forward every message without policy evaluation (skeleton mode; useful for validating the relay)")
	noInteractive := fs.Bool("no-interactive", false, "Auto-deny every ask decision instead of prompting (reserved for the TTY approver in issue #29)")
	debug := fs.Bool("debug", false, "Log every forwarded message to stderr")
	if err := fs.Parse(args); err != nil {
		return err
	}
	_ = noInteractive // The current default approver is deny-all; the TTY
	// approver landing in #29 will branch on this flag.

	rest := fs.Args()
	if len(rest) == 0 {
		return errors.New("proxy: a downstream command is required after `--` (e.g. `agentfence proxy --policy policy.yaml -- node server.js`)")
	}
	cmdName := rest[0]
	cmdArgs := rest[1:]

	var eng *engine.Engine
	if !*passthrough {
		if *policyPath == "" {
			return errors.New("--policy is required (or pass --passthrough to run the relay without enforcement)")
		}
		p, err := policy.LoadFile(*policyPath)
		if err != nil {
			return err
		}
		eng, err = engine.New(p)
		if err != nil {
			return err
		}
	}

	auditOut, closeAudit, err := openAuditOutput(*auditLogPath, *tamperEvident)
	if err != nil {
		return err
	}
	defer closeAudit()
	aw := audit.NewWriterOptions(auditOut, audit.Options{TamperEvident: *tamperEvident})

	opts := proxy.Options{
		Engine:      eng,
		AuditWriter: aw,
		Approver:    proxy.DenyAllApprover{},
		Passthrough: *passthrough,
		Debug:       *debug,
		Logger:      os.Stderr,
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	// Return the proxy.Run error unchanged. When the downstream MCP server
	// exits non-zero, it is an *exec.ExitError; main() detects that and
	// exits with the same code. Returning here (instead of calling
	// os.Exit inside runProxy) lets the deferred closeAudit() flush and
	// close the audit log before the process exits.
	return proxy.Run(ctx, cmdName, cmdArgs, opts)
}

// openAuditOutput returns the audit destination Writer + a close func. When
// auditLogPath is empty, audit events are discarded (the proxy MUST NOT
// interleave audit JSONL with the agent's stdout, which is reserved for
// JSON-RPC responses). The tamper-evident flag with no log file triggers a
// stderr warning consistent with `check`.
//
// New files are created with 0o600 (owner-read/write) so audit events —
// which can contain redacted-but-still-sensitive tool arguments — do not
// inherit a permissive umask. Pre-existing files are opened in append mode
// without altering their permissions, on the assumption that the operator
// chose those bits deliberately.
func openAuditOutput(auditLogPath string, tamperEvident bool) (io.Writer, func(), error) {
	if auditLogPath == "" {
		if tamperEvident {
			fmt.Fprintln(os.Stderr, "AgentFence: warning: --tamper-evident without --audit-log discards audit events; nothing to verify.")
		}
		return io.Discard, func() {}, nil
	}
	f, err := os.OpenFile(auditLogPath, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return nil, nil, err
	}
	return f, func() { _ = f.Close() }, nil
}

// runPolicySubcmd dispatches policy sub-commands: test, validate.
func runPolicySubcmd(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("policy requires a subcommand: test, validate")
	}
	switch args[0] {
	case "test":
		return runPolicyTest(args[1:])
	case "validate":
		return runValidate(args[1:])
	default:
		return fmt.Errorf("unknown policy subcommand %q; valid: test, validate", args[0])
	}
}

// runPolicyTest evaluates a YAML fixture file against a policy and reports pass/fail.
func runPolicyTest(args []string) error {
	fs := flag.NewFlagSet("policy test", flag.ContinueOnError)
	policyPath := fs.String("policy", "", "Path to policy YAML")
	testsPath := fs.String("tests", "", "Path to test fixture YAML")
	verbose := fs.Bool("verbose", false, "Print decision reason alongside each result")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *policyPath == "" || *testsPath == "" {
		return errors.New("--policy and --tests are required")
	}

	p, err := policy.LoadFile(*policyPath)
	if err != nil {
		return err
	}
	eng, err := engine.New(p)
	if err != nil {
		return err
	}

	b, err := os.ReadFile(*testsPath)
	if err != nil {
		return err
	}
	fixture, err := policy.ParsePolicyTestFixture(b)
	if err != nil {
		return err
	}

	failed := 0
	for _, tc := range fixture.Tests {
		arguments := tc.Arguments
		if arguments == nil {
			arguments = map[string]interface{}{}
		}
		call := policy.ToolCall{
			ID:        tc.ID,
			Tool:      tc.Tool,
			Arguments: arguments,
		}
		result, _ := eng.Evaluate(call)

		if result.Decision == tc.Expect {
			if *verbose {
				fmt.Printf("PASS: %s (%s)\n", tc.ID, result.Reason)
			} else {
				fmt.Printf("PASS: %s\n", tc.ID)
			}
		} else {
			fmt.Printf("FAIL: %s (expected %s, got %s)\n", tc.ID, tc.Expect, result.Decision)
			failed++
		}
	}

	if failed > 0 {
		return fmt.Errorf("%d test(s) failed", failed)
	}
	return nil
}
