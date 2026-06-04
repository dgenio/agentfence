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
	"time"

	"github.com/dgenio/agentfence/internal/approval"
	"github.com/dgenio/agentfence/internal/audit"
	"github.com/dgenio/agentfence/internal/demo"
	"github.com/dgenio/agentfence/internal/engine"
	"github.com/dgenio/agentfence/internal/interop"
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
	if err := runRoot(os.Args[1:]); err != nil {
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

func runRoot(args []string) error {
	// Handle --version / -version before the subcommand switch so it works
	// regardless of argument position.
	for _, arg := range args {
		if arg == "--version" || arg == "-version" {
			runVersion()
			return nil
		}
	}

	if len(args) == 0 {
		printUsage()
		return nil
	}
	if isHelpArg(args[0]) {
		printUsage()
		return nil
	}
	if args[0] == "help" {
		if len(args) == 1 {
			printUsage()
			return nil
		}
		return runRoot([]string{args[1], "--help"})
	}

	var err error
	switch args[0] {
	case "audit":
		err = runAuditSubcmd(args[1:])
	case "check":
		err = runCheck(args[1:])
	case "demo":
		err = demo.Run(os.Stdout)
	case "explain":
		err = runExplain(args[1:])
	case "init":
		err = runInit()
	case "policy":
		err = runPolicySubcmd(args[1:])
	case "proxy":
		err = runProxy(args[1:])
	case "validate":
		err = runValidate(args[1:])
	case "version":
		runVersion()
		return nil
	default:
		printUsage()
		err = fmt.Errorf("unknown command: %s", args[0])
	}

	return err
}

func isHelpArg(arg string) bool {
	return arg == "--help" || arg == "-h"
}

func handleFlagParseErr(err error) error {
	if errors.Is(err, flag.ErrHelp) {
		return nil
	}
	return err
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
	dryRun := fs.Bool("dry-run", false, "Evaluate and audit without enforcing: ask decisions are not prompted, and --fail-on does not change the exit code")
	noInteractive := fs.Bool("no-interactive", false, "Do not prompt the operator on ask decisions; auto-deny instead")
	approvalTimeout := fs.Duration("approval-timeout", 0, "Maximum time to wait for an ask response (e.g. 30s, 2m). 0 means wait forever; recommended for CI is 30s with --no-interactive")
	if err := fs.Parse(args); err != nil {
		return handleFlagParseErr(err)
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
	closeAudit := func() {}
	auditOptions := audit.Options{TamperEvident: *tamperEvident}
	if *auditLogPath != "" {
		var err error
		auditOut, closeAudit, auditOptions, err = openAuditOutput(*auditLogPath, *tamperEvident)
		if err != nil {
			return err
		}
		defer closeAudit()
	} else if *outputMode == "text" {
		auditOut = os.Stdout
	}

	if *tamperEvident && *auditLogPath == "" {
		fmt.Fprintln(os.Stderr, "AgentFence: warning: --tamper-evident without --audit-log produces a chain interleaved with other output; verification will not be reliable.")
	}

	aw := audit.NewWriterOptions(auditOut, auditOptions)

	// Approver selection. In dry-run we never prompt; otherwise --no-interactive
	// forces DenyAllApprover, and the default opens a real TTY.
	var approver approval.Approver
	switch {
	case *dryRun:
		approver = nil // never invoked in dry-run mode
	case *noInteractive:
		approver = approval.DenyAllApprover{}
	default:
		tty, err := approval.NewTTYApprover()
		if err != nil {
			return fmt.Errorf("approval: %w", err)
		}
		defer tty.Close()
		approver = tty
	}

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
			if err := aw.Write(audit.NewErrorEvent(lineNum, err.Error())); err != nil {
				return err
			}
			counts[policy.DecisionDeny]++
			continue
		}

		res, event := eng.Evaluate(call)

		// On ask, convert to allow/deny via the approver — unless we're in
		// dry-run, in which case ask is recorded verbatim with mode=dry_run.
		if res.Decision == policy.DecisionAsk && !*dryRun {
			res, event = resolveAsk(approver, call, res, event, *approvalTimeout, *noInteractive)
		}

		if *dryRun {
			event.Mode = audit.ModeDryRun
		}

		summary := DecisionSummary{
			ID:       call.ID,
			Tool:     call.Tool,
			Decision: res.Decision,
			Reason:   res.Reason,
		}

		switch *outputMode {
		case "text":
			suffix := ""
			if *dryRun {
				suffix = " [dry-run]"
			}
			fmt.Printf("%s %s -> %s (%s)%s\n", call.ID, call.Tool, res.Decision, res.Reason, suffix)
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

	// --fail-on: exit 1 if any call matched a gated decision. In dry-run we
	// report what would have failed but do not propagate the non-zero exit —
	// the whole point of dry-run is "evaluate without enforcing."
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
			if *dryRun {
				fmt.Fprintf(os.Stderr, "AgentFence: dry-run: %d call(s) would have matched --fail-on criteria (%s)\n", matched, strings.Join(gated, ", "))
			} else {
				fmt.Fprintf(os.Stderr, "AgentFence: %d call(s) matched --fail-on criteria (%s)\n", matched, strings.Join(gated, ", "))
				return fmt.Errorf("%d call(s) matched --fail-on criteria", matched)
			}
		}
	}

	return nil
}

// resolveAsk converts an ask decision into a concrete allow or deny by calling
// the approver. The audit event is updated in place to reflect the final
// decision and reason. A zero timeout means "wait forever."
func resolveAsk(approver approval.Approver, call policy.ToolCall, res policy.EvaluationResult, event audit.Event, timeout time.Duration, noInteractive bool) (policy.EvaluationResult, audit.Event) {
	ctx := context.Background()
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}

	approved, err := approver.Request(ctx, call)
	switch {
	case approved:
		res.Decision = policy.DecisionAllow
		res.Reason = approval.ReasonApprovedInteractively
	case errors.Is(err, context.DeadlineExceeded):
		res.Decision = policy.DecisionDeny
		res.Reason = approval.ReasonApprovalTimeout
	case errors.Is(err, context.Canceled):
		res.Decision = policy.DecisionDeny
		res.Reason = approval.ReasonApprovalCancelled
	case err != nil:
		fmt.Fprintf(os.Stderr, "AgentFence: approval I/O error for [%s] %s: %v\n", call.ID, call.Tool, err)
		res.Decision = policy.DecisionDeny
		res.Reason = approval.ReasonApprovalIOError
	case noInteractive:
		res.Decision = policy.DecisionDeny
		res.Reason = approval.ReasonNonInteractive
	default:
		res.Decision = policy.DecisionDeny
		res.Reason = approval.ReasonDeniedInteractively
	}
	event.Decision = res.Decision
	event.Reason = res.Reason
	return res, event
}

func runValidate(args []string) error {
	fs := flag.NewFlagSet("validate", flag.ContinueOnError)
	policyPath := fs.String("policy", "", "Path to policy YAML")
	if err := fs.Parse(args); err != nil {
		return handleFlagParseErr(err)
	}
	if *policyPath == "" {
		return errors.New("--policy is required")
	}

	errs := policy.ValidateFileStrict(*policyPath)
	if len(errs) > 0 {
		for _, e := range errs {
			fmt.Fprintf(os.Stderr, "%s\n", e.Error())
		}
		return fmt.Errorf("%s: %d validation error(s): %s", *policyPath, len(errs), errs[0])
	}

	fmt.Printf("%s: OK\n", *policyPath)
	return nil
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
	fmt.Println("  agentfence check   --policy <file> --call <jsonl> [--audit-log <file>] [--output text|json|jsonl] [--fail-on deny|ask|deny,ask] [--tamper-evident] [--dry-run] [--no-interactive] [--approval-timeout <duration>]")
	fmt.Println("  agentfence explain --policy <file> --tool <name> [--args <json>] [--output text|json]")
	fmt.Println("  agentfence policy  test     --policy <file> --tests <yaml> [--verbose]")
	fmt.Println("  agentfence policy  validate --policy <file>")
	fmt.Println("  agentfence proxy   --policy <file> [--audit-log <file>] [--tamper-evident] [--passthrough] [--no-interactive] [--debug] -- <command> [args...]")
	fmt.Println("  agentfence validate --policy <file>")
	fmt.Println("  agentfence audit   verify    --log <file>")
	fmt.Println("  agentfence audit   summarize --log <file> [--output text|json] [--top N]")
	fmt.Println("  agentfence audit   export    --log <file> [--format weaver-trace]")
	fmt.Println("  agentfence version")
	fmt.Println("  agentfence demo")
	fmt.Println("  agentfence init")
	fmt.Println("")
	fmt.Println("See docs/modes.md for detection / prevention / audit-only / dry-run mode definitions.")
}

// runExplain evaluates a single tool call and prints a human-readable decision trace.
func runExplain(args []string) error {
	fs := flag.NewFlagSet("explain", flag.ContinueOnError)
	policyPath := fs.String("policy", "", "Path to policy YAML")
	toolName := fs.String("tool", "", "Tool name to explain (e.g. filesystem.write)")
	argsStr := fs.String("args", "{}", "JSON object of tool call arguments")
	outputMode := fs.String("output", "text", "Output mode: text, json")
	if err := fs.Parse(args); err != nil {
		return handleFlagParseErr(err)
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
			Tool     string   `json:"tool"`
			Decision string   `json:"decision"`
			Reason   string   `json:"reason"`
			Trace    []string `json:"trace"`
		}{
			Tool:     *toolName,
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

// runAuditSubcmd dispatches audit sub-commands: verify, summarize, export.
func runAuditSubcmd(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("audit requires a subcommand: verify, summarize, export")
	}
	if isHelpArg(args[0]) {
		fmt.Println("Usage:")
		fmt.Println("  agentfence audit   verify    --log <file>")
		fmt.Println("  agentfence audit   summarize --log <file> [--output text|json] [--top N]")
		fmt.Println("  agentfence audit   export    --log <file> [--format weaver-trace]")
		return nil
	}
	switch args[0] {
	case "verify":
		return runAuditVerify(args[1:])
	case "summarize":
		return runAuditSummarize(args[1:])
	case "export":
		return runAuditExport(args[1:])
	default:
		return fmt.Errorf("unknown audit subcommand %q; valid: verify, summarize, export", args[0])
	}
}

// runAuditExport reads an existing JSONL audit log and writes a weaver-spec-aligned
// trace stream to stdout (a PolicyDecision and matching TraceEvent per event). The
// native log is read-only, so its hash chain stays verifiable; see docs/interop.md.
func runAuditExport(args []string) error {
	fs := flag.NewFlagSet("audit export", flag.ContinueOnError)
	logPath := fs.String("log", "", "Path to audit JSONL log to export")
	format := fs.String("format", "weaver-trace", "Export format: weaver-trace")
	if err := fs.Parse(args); err != nil {
		return handleFlagParseErr(err)
	}
	if *logPath == "" {
		return errors.New("--log is required")
	}
	if *format != "weaver-trace" {
		return fmt.Errorf("unknown --format %q; valid values: weaver-trace", *format)
	}

	f, err := os.Open(*logPath)
	if err != nil {
		return err
	}
	defer f.Close()

	if _, err := interop.ExportTraces(f, os.Stdout); err != nil {
		return err
	}
	return nil
}

// runAuditSummarize aggregates an existing JSONL audit log and prints either a
// human-readable summary or a JSON document with the same fields. Malformed
// lines are counted as Malformed but never abort the run, so summarising a
// partially corrupted log is still useful.
func runAuditSummarize(args []string) error {
	fs := flag.NewFlagSet("audit summarize", flag.ContinueOnError)
	logPath := fs.String("log", "", "Path to audit JSONL log to summarise")
	outputMode := fs.String("output", "text", "Output mode: text, json")
	topN := fs.Int("top", 10, "Maximum number of rows in each top-N section")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *logPath == "" {
		return errors.New("--log is required")
	}
	switch *outputMode {
	case "text", "json":
	default:
		return fmt.Errorf("unknown --output mode %q; valid values: text, json", *outputMode)
	}

	f, err := os.Open(*logPath)
	if err != nil {
		return err
	}
	defer f.Close()

	summary, err := audit.Summarize(f, *topN)
	if err != nil {
		return err
	}

	switch *outputMode {
	case "json":
		b, err := json.MarshalIndent(summary, "", "  ")
		if err != nil {
			return fmt.Errorf("audit summarize: json marshal: %w", err)
		}
		if _, err := fmt.Fprintf(os.Stdout, "%s\n", b); err != nil {
			return fmt.Errorf("audit summarize: write output: %w", err)
		}
	default:
		if err := summary.FormatText(os.Stdout); err != nil {
			return err
		}
	}
	return nil
}

// runAuditVerify checks the tamper-evident hash chain of a JSONL audit log.
func runAuditVerify(args []string) error {
	fs := flag.NewFlagSet("audit verify", flag.ContinueOnError)
	logPath := fs.String("log", "", "Path to audit JSONL log to verify")
	if err := fs.Parse(args); err != nil {
		return handleFlagParseErr(err)
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
	case errors.Is(err, audit.ErrPartialChain):
		var pe *audit.PartialChainError
		if errors.As(err, &pe) {
			fmt.Printf("PARTIAL: %d event(s); chain starts at event %d; events 1..%d are not integrity-protected\n", pe.Total, pe.ChainStartEvent, pe.ChainStartEvent-1)
			return fmt.Errorf("audit verify: %s", pe.Error())
		}
		return fmt.Errorf("audit verify: %w", err)
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
		return handleFlagParseErr(err)
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

	auditOut, closeAudit, auditOptions, err := openAuditOutput(*auditLogPath, *tamperEvident)
	if err != nil {
		return err
	}
	defer closeAudit()
	aw := audit.NewWriterOptions(auditOut, auditOptions)

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

// openAuditOutput returns the audit destination Writer, close func, and writer
// options. When auditLogPath is empty, audit events are discarded (the proxy MUST NOT
// interleave audit JSONL with the agent's stdout, which is reserved for
// JSON-RPC responses). The tamper-evident flag with no log file triggers a
// stderr warning consistent with `check`.
//
// New files are created with 0o600 (owner-read/write) so audit events —
// which can contain redacted-but-still-sensitive tool arguments — do not
// inherit a permissive umask. Pre-existing files are opened in append mode
// without altering their permissions, on the assumption that the operator
// chose those bits deliberately.
func openAuditOutput(auditLogPath string, tamperEvident bool) (io.Writer, func(), audit.Options, error) {
	options := audit.Options{TamperEvident: tamperEvident}
	if auditLogPath == "" {
		if tamperEvident {
			fmt.Fprintln(os.Stderr, "AgentFence: warning: --tamper-evident without --audit-log discards audit events; nothing to verify.")
		}
		return io.Discard, func() {}, options, nil
	}
	flags := os.O_WRONLY | os.O_CREATE | os.O_APPEND
	if tamperEvident {
		flags = os.O_RDWR | os.O_CREATE | os.O_APPEND
	}
	f, err := os.OpenFile(auditLogPath, flags, 0o600)
	if err != nil {
		return nil, nil, audit.Options{}, err
	}
	if tamperEvident {
		if _, err := f.Seek(0, io.SeekStart); err != nil {
			_ = f.Close()
			return nil, nil, audit.Options{}, err
		}
		lastHash, eventCount, firstChained, err := audit.LastChainState(f)
		if err != nil {
			_ = f.Close()
			return nil, nil, audit.Options{}, fmt.Errorf("audit: existing log chain: %w", err)
		}
		// Refuse to append a chain unless the existing log is empty OR
		// already fully chained from event 1. Two cases get rejected here:
		//
		//  1. fully unchained log (firstChained == 0): appending would
		//     produce a mixed log whose prefix is not integrity-protected.
		//  2. partial-chain log (firstChained > 1): a previous run already
		//     produced the mixed state; continuing the chain perpetuates the
		//     unprotected prefix instead of fixing it.
		//
		// In both cases `audit verify` would later surface the file as
		// PARTIAL; failing early at write time is the symmetric defence.
		if eventCount > 0 && firstChained != 1 {
			_ = f.Close()
			if firstChained == 0 {
				return nil, nil, audit.Options{}, fmt.Errorf("audit: cannot enable --tamper-evident on existing unchained log %q (%d unchained event(s)); use a new file or convert the log first", auditLogPath, eventCount)
			}
			return nil, nil, audit.Options{}, fmt.Errorf("audit: cannot enable --tamper-evident on existing partial-chain log %q (chain starts at event %d of %d; events 1..%d are not integrity-protected); use a new file or convert the log first", auditLogPath, firstChained, eventCount, firstChained-1)
		}
		options.InitialPrevHash = lastHash
		if _, err := f.Seek(0, io.SeekEnd); err != nil {
			_ = f.Close()
			return nil, nil, audit.Options{}, err
		}
	}
	return f, func() { _ = f.Close() }, options, nil
}

// runPolicySubcmd dispatches policy sub-commands: test, validate.
func runPolicySubcmd(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("policy requires a subcommand: test, validate")
	}
	if isHelpArg(args[0]) {
		fmt.Println("Usage:")
		fmt.Println("  agentfence policy  test     --policy <file> --tests <yaml> [--verbose]")
		fmt.Println("  agentfence policy  validate --policy <file>")
		return nil
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
		return handleFlagParseErr(err)
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
