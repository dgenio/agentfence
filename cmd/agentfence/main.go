package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
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
	"github.com/dgenio/agentfence/internal/httpproxy"
	"github.com/dgenio/agentfence/internal/interop"
	"github.com/dgenio/agentfence/internal/metrics"
	"github.com/dgenio/agentfence/internal/oplog"
	"github.com/dgenio/agentfence/internal/packs"
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

// checkGateSummary is the machine-readable artifact written by `check
// --summary <path>`. It is independent of --output so CI can consume a stable
// gate summary (per-decision counts, top denied tools/reasons, and whether the
// gate failed) without parsing the decision stream or recomputing it with jq.
type checkGateSummary struct {
	Total            int               `json:"total"`
	ParseErrors      int               `json:"parse_errors"`
	ByDecision       map[string]int    `json:"by_decision"`
	TopDeniedTools   []gateToolCount   `json:"top_denied_tools"`
	TopDeniedReasons []gateReasonCount `json:"top_denied_reasons"`
	FailOn           []string          `json:"fail_on,omitempty"`
	Matched          int               `json:"matched"`
	Failed           bool              `json:"failed"`
	DryRun           bool              `json:"dry_run"`
}

type gateToolCount struct {
	Tool  string `json:"tool"`
	Count int    `json:"count"`
}

type gateReasonCount struct {
	Reason string `json:"reason"`
	Count  int    `json:"count"`
}

// decisionCounts renders the per-decision tally with all three classes always
// present, so the JSON shape is stable regardless of which decisions occurred.
func decisionCounts(counts map[policy.Decision]int) map[string]int {
	return map[string]int{
		"allow": counts[policy.DecisionAllow],
		"deny":  counts[policy.DecisionDeny],
		"ask":   counts[policy.DecisionAsk],
	}
}

func topToolRows(m map[string]int, topN int) []gateToolCount {
	keys := sortedByCount(m, topN)
	rows := make([]gateToolCount, len(keys))
	for i, k := range keys {
		rows[i] = gateToolCount{Tool: k, Count: m[k]}
	}
	return rows
}

func topReasonRows(m map[string]int, topN int) []gateReasonCount {
	keys := sortedByCount(m, topN)
	rows := make([]gateReasonCount, len(keys))
	for i, k := range keys {
		rows[i] = gateReasonCount{Reason: k, Count: m[k]}
	}
	return rows
}

// sortedByCount returns the map keys ordered by count descending, then key
// ascending for deterministic ties, bounded to topN (non-positive = all).
func sortedByCount(m map[string]int, topN int) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if m[keys[i]] != m[keys[j]] {
			return m[keys[i]] > m[keys[j]]
		}
		return keys[i] < keys[j]
	})
	if topN > 0 && len(keys) > topN {
		keys = keys[:topN]
	}
	return keys
}

// writeGateSummary writes the gate summary as indented JSON to path, or to
// stderr when path is "-" (stdout is reserved for the --output decision stream).
func writeGateSummary(path string, gs checkGateSummary) error {
	b, err := json.MarshalIndent(gs, "", "  ")
	if err != nil {
		return fmt.Errorf("check: gate summary marshal: %w", err)
	}
	if path == "-" {
		if _, err := fmt.Fprintf(os.Stderr, "%s\n", b); err != nil {
			return fmt.Errorf("check: write gate summary: %w", err)
		}
		return nil
	}
	if err := os.WriteFile(path, append(b, '\n'), 0o644); err != nil {
		return fmt.Errorf("check: write gate summary: %w", err)
	}
	return nil
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
		err = runInit(args[1:])
	case "policy":
		err = runPolicySubcmd(args[1:])
	case "proxy":
		err = runProxy(args[1:])
	case "proxy-http":
		err = runProxyHTTP(args[1:])
	case "validate":
		err = runValidate(args[1:])
	case "version":
		err = runVersionCmd(args[1:])
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

// runVersionCmd is the `version` subcommand. It takes no flags or positional
// arguments; unrecognised flags surface an error and --help prints brief help,
// rather than the previous behaviour of silently ignoring whatever followed.
func runVersionCmd(args []string) error {
	fs := flag.NewFlagSet("version", flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprintln(fs.Output(), "Usage: agentfence version")
		fmt.Fprintln(fs.Output(), "")
		fmt.Fprintln(fs.Output(), "Print the AgentFence version, OS, and architecture. Takes no arguments.")
	}
	if err := fs.Parse(args); err != nil {
		return handleFlagParseErr(err)
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("version takes no arguments; got %q", fs.Arg(0))
	}
	runVersion()
	return nil
}

func runCheck(args []string) error {
	fs := flag.NewFlagSet("check", flag.ContinueOnError)
	policyPath := fs.String("policy", "", "Path to policy YAML")
	callPath := fs.String("call", "", "Path to JSONL tool-call input")
	auditLogPath := fs.String("audit-log", "", "Optional path to write audit JSONL")
	outputMode := fs.String("output", "text", "Output mode: text, json, jsonl")
	failOn := fs.String("fail-on", "", "Comma-separated decisions to fail on: deny, ask")
	logFormat := fs.String("log-format", "text", "Operational log format for stderr diagnostics: text (default, unchanged) or json. Distinct from the audit log and the decision output on stdout")
	emitMetrics := fs.Bool("metrics", false, "Print a decision-metrics summary (counts by decision/tool/reason-code, taint escalations, approval outcomes) to stderr on exit")
	summaryPath := fs.String("summary", "", "Write a machine-readable JSON gate summary (per-decision counts, top denied tools/reasons) independent of --output. Pass a file path for a clean artifact (written even when --fail-on fails); pass - to write to stderr, which on a gate failure also carries diagnostic lines and is not pure JSON")
	tamperEvident := fs.Bool("tamper-evident", false, "Write a hash-chained audit log (use with --audit-log; verify with 'agentfence audit verify')")
	dryRun := fs.Bool("dry-run", false, "Evaluate and audit without enforcing: ask decisions are not prompted, and --fail-on does not change the exit code")
	noInteractive := fs.Bool("no-interactive", false, "Do not prompt the operator on ask decisions; auto-deny instead")
	approvalTimeout := fs.Duration("approval-timeout", 0, "Maximum time to wait for an ask response (e.g. 30s, 2m). 0 means wait forever; recommended for CI is 30s with --no-interactive")
	signKey := fs.String("sign-key", "", "Path to an Ed25519 private key (PEM) to sign each audit event; verify with 'agentfence audit verify --pubkey'")
	auditMaxSize := fs.Int64("audit-max-size", 0, "Rotate the audit log once it reaches this many bytes (0 = no size rotation; requires --audit-log)")
	auditMaxAge := fs.Duration("audit-max-age", 0, "Rotate the audit log once it has been open this long, e.g. 24h (0 = no age rotation; requires --audit-log)")
	auditKeep := fs.Int("audit-keep", 0, "Number of rotated audit segments to retain (0 = keep all)")
	auditFsync := fs.Bool("audit-fsync", false, "fsync the audit log to disk after every event so a decision survives a crash or power loss (slower; requires --audit-log)")
	var auditSinks stringSliceFlag
	fs.Var(&auditSinks, "audit-sink", "Ship audit events to an external sink; repeatable. Schemes: http(s)://…, syslog://host:port, syslog+tcp://host:port")
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

	logFmt, err := oplog.ParseFormat(*logFormat)
	if err != nil {
		return err
	}
	// Operational logger for stderr diagnostics. In text mode it stays silent so
	// the existing byte-for-byte stderr contract is preserved; structured
	// per-line and gate events are emitted only under --log-format json.
	oplogger := oplog.New(os.Stderr, logFmt, false)
	counters := metrics.New()

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
	// for text mode preserve the existing behaviour of writing to stdout. Signing
	// and external sinks apply regardless of the local destination.
	var noFileWriter io.Writer = io.Discard
	if *outputMode == "text" {
		noFileWriter = os.Stdout
	}
	auditOut, closeAudit, auditOptions, err := openAuditOutput(auditConfig{
		path:          *auditLogPath,
		tamperEvident: *tamperEvident,
		signKeyPath:   *signKey,
		maxSizeBytes:  *auditMaxSize,
		maxAge:        *auditMaxAge,
		keep:          *auditKeep,
		sinkSpecs:     auditSinks,
		fsync:         *auditFsync,
		noFileWriter:  noFileWriter,
	})
	if err != nil {
		return err
	}
	defer closeAudit()

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
	deniedTools := map[string]int{}
	deniedReasons := map[string]int{}
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
			counters.Record(policy.DecisionDeny, "", policy.ReasonCodeParseError)
			if logFmt == oplog.FormatJSON {
				oplogger.Warn("tool-call line failed to parse", "line", lineNum, "err", err.Error())
			}
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
		counters.Record(res.Decision, call.Tool, event.ReasonCode)
		if res.Decision == policy.DecisionDeny {
			if call.Tool != "" {
				deniedTools[call.Tool]++
			}
			deniedReasons[res.Reason]++
		}
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

	// Compute the --fail-on tally once: it drives both the optional gate summary
	// and the exit decision below.
	matched := 0
	gated := make([]string, 0, len(failOnSet))
	for d := range failOnSet {
		matched += counts[d]
		gated = append(gated, string(d))
	}
	sort.Strings(gated)
	gateFailed := !*dryRun && len(failOnSet) > 0 && matched > 0

	// --summary: emit a machine-readable gate summary independent of --output,
	// so CI can surface "what was denied" without a second `audit summarize`
	// pass or bespoke jq over the decision stream. Written before the --fail-on
	// exit so the artifact exists even when the gate fails.
	if *summaryPath != "" {
		gs := checkGateSummary{
			Total:            lineNum,
			ParseErrors:      parseErrors,
			ByDecision:       decisionCounts(counts),
			TopDeniedTools:   topToolRows(deniedTools, 10),
			TopDeniedReasons: topReasonRows(deniedReasons, 10),
			FailOn:           gated,
			Matched:          matched,
			Failed:           gateFailed,
			DryRun:           *dryRun,
		}
		if err := writeGateSummary(*summaryPath, gs); err != nil {
			return err
		}
	}

	// Decision-metrics summary (opt-in) on stderr, before the gate exit so it is
	// emitted even when --fail-on fails. Stderr keeps it out of a --output
	// json/jsonl stream on stdout.
	if *emitMetrics {
		if err := counters.Snapshot().FormatText(os.Stderr); err != nil {
			return err
		}
	}

	// --fail-on: exit 1 if any call matched a gated decision. In dry-run we
	// report what would have failed but do not propagate the non-zero exit —
	// the whole point of dry-run is "evaluate without enforcing."
	if len(failOnSet) > 0 && matched > 0 {
		if logFmt == oplog.FormatJSON {
			oplogger.Warn("fail-on criteria matched", "matched", matched, "fail_on", gated, "dry_run", *dryRun)
		}
		if *dryRun {
			if logFmt != oplog.FormatJSON {
				fmt.Fprintf(os.Stderr, "AgentFence: dry-run: %d call(s) would have matched --fail-on criteria (%s)\n", matched, strings.Join(gated, ", "))
			}
		} else {
			if logFmt != oplog.FormatJSON {
				fmt.Fprintf(os.Stderr, "AgentFence: %d call(s) matched --fail-on criteria (%s)\n", matched, strings.Join(gated, ", "))
			}
			return fmt.Errorf("%d call(s) matched --fail-on criteria", matched)
		}
	}

	return nil
}

// resolveAsk converts an ask decision into a concrete allow or deny by calling
// the approver. The audit event is updated in place to reflect the final
// decision and reason. A zero timeout means "wait forever."
func resolveAsk(approver approval.Approver, call policy.ToolCall, res policy.EvaluationResult, event audit.Event, timeout time.Duration, noInteractive bool) (policy.EvaluationResult, audit.Event) {
	outcome, err := approval.Resolve(context.Background(), approver, call, timeout, noInteractive)
	if outcome.Approved {
		res.Decision = policy.DecisionAllow
	} else {
		res.Decision = policy.DecisionDeny
	}
	res.Reason = outcome.Reason
	res.ReasonCode = outcome.Code
	if outcome.Reason == approval.ReasonApprovalIOError {
		fmt.Fprintf(os.Stderr, "AgentFence: approval I/O error for [%s] %s: %v\n", call.ID, call.Tool, err)
	}
	event.Decision = res.Decision
	event.Reason = res.Reason
	event.ReasonCode = res.ReasonCode
	return res, event
}

// newProxyApprover builds the approver for the long-running proxies. With
// --no-interactive it returns the shared fail-closed DenyAllApprover; otherwise
// it opens a TTYApprover bound to /dev/tty. Unlike check, the proxies must NOT
// fall back to os.Stdin for prompts: the stdio proxy's stdin is the agent's
// JSON-RPC channel, so reading approvals there would corrupt the protocol.
// When no controlling terminal is available, this fails with a message telling
// the operator to re-run with --no-interactive. The returned cleanup closes
// any TTY handle and is always safe to call.
func newProxyApprover(noInteractive bool) (approval.Approver, func(), error) {
	if noInteractive {
		return approval.DenyAllApprover{}, func() {}, nil
	}
	tty, err := approval.NewTTYApproverStrict()
	if err != nil {
		return nil, func() {}, fmt.Errorf("interactive approval needs a terminal (/dev/tty); re-run with --no-interactive for unattended use: %w", err)
	}
	return tty, func() { _ = tty.Close() }, nil
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

func runInit(args []string) error {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	packList := fs.String("pack", "", "Comma-separated policy packs to scaffold from (e.g. filesystem,github,shell). Run with an unknown pack to list the available packs.")
	fs.Usage = func() {
		fmt.Fprintln(fs.Output(), "Usage: agentfence init [--pack <names>]")
		fmt.Fprintln(fs.Output(), "")
		fmt.Fprintln(fs.Output(), "Write a starter policy to agentfence.yaml in the current directory.")
		fmt.Fprintln(fs.Output(), "With --pack, scaffold from one or more curated policy packs instead;")
		fmt.Fprintf(fs.Output(), "available packs: %s.\n", strings.Join(packs.Names(), ", "))
		fmt.Fprintln(fs.Output(), "Fails if any target file already exists.")
	}
	if err := fs.Parse(args); err != nil {
		return handleFlagParseErr(err)
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("init takes no positional arguments; got %q", fs.Arg(0))
	}

	if *packList != "" {
		return runInitFromPacks(*packList)
	}

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

// runInitFromPacks scaffolds an agentfence.yaml that imports one curated policy
// pack file per selected pack. The pack files are written next to it so the
// existing import-resolution machinery (and `agentfence validate`) works on the
// result. Users layer their own rules in agentfence.yaml; a redeclared tool key
// there overrides the inherited pack rule.
func runInitFromPacks(packList string) error {
	names, err := parsePackList(packList)
	if err != nil {
		return err
	}

	// Refuse to clobber: check every target file before writing any of them.
	const rootFile = "agentfence.yaml"
	targets := []string{rootFile}
	packFiles := make([]string, len(names))
	for i, name := range names {
		packFiles[i] = fmt.Sprintf("agentfence.%s.yaml", name)
		targets = append(targets, packFiles[i])
	}
	for _, t := range targets {
		if _, err := os.Stat(t); err == nil {
			return fmt.Errorf("%s already exists", t)
		}
	}

	for i, name := range names {
		body, _ := packs.Policy(name) // existence already checked by parsePackList
		if err := os.WriteFile(packFiles[i], body, 0o644); err != nil {
			return err
		}
		fmt.Printf("Created %s\n", packFiles[i])
	}

	if err := os.WriteFile(rootFile, []byte(scaffoldRootPolicy(names, packFiles)), 0o644); err != nil {
		return err
	}
	fmt.Printf("Created %s\n", rootFile)
	return nil
}

// parsePackList splits a comma-separated pack list, validating each name and
// rejecting duplicates. An unknown name returns an error that lists the
// available packs so the message doubles as discovery.
func parsePackList(packList string) ([]string, error) {
	seen := map[string]bool{}
	var names []string
	for _, raw := range strings.Split(packList, ",") {
		name := strings.TrimSpace(raw)
		if name == "" {
			continue
		}
		if !packs.Exists(name) {
			return nil, fmt.Errorf("unknown policy pack %q; available packs: %s", name, strings.Join(packs.Names(), ", "))
		}
		if seen[name] {
			return nil, fmt.Errorf("policy pack %q listed more than once", name)
		}
		seen[name] = true
		names = append(names, name)
	}
	if len(names) == 0 {
		return nil, fmt.Errorf("--pack: no pack names given; available packs: %s", strings.Join(packs.Names(), ", "))
	}
	return names, nil
}

// scaffoldRootPolicy renders the importing agentfence.yaml that ties the
// selected pack files together.
func scaffoldRootPolicy(names, packFiles []string) string {
	var b strings.Builder
	b.WriteString("version: \"0.1\"\n\n")
	fmt.Fprintf(&b, "# Scaffolded from policy packs: %s.\n", strings.Join(names, ", "))
	b.WriteString("# Pack rules are inherited via the imports below. To override one, redeclare\n")
	b.WriteString("# the tool key under `tools:` here — the importing policy always wins.\n")
	b.WriteString("imports:\n")
	for _, pf := range packFiles {
		fmt.Fprintf(&b, "  - %s\n", pf)
	}
	b.WriteString("\ndefaults:\n  decision: deny\n\n")
	b.WriteString("# Add your own tool rules here.\ntools: {}\n")
	return b.String()
}

func printUsage() {
	fmt.Println("Usage:")
	fmt.Println("  agentfence check   --policy <file> --call <jsonl> [--audit-log <file>] [--output text|json|jsonl] [--log-format text|json] [--metrics] [--fail-on deny|ask|deny,ask] [--summary <file|->] [--tamper-evident] [--sign-key <file>] [--audit-max-size <bytes>] [--audit-max-age <dur>] [--audit-keep <n>] [--audit-fsync] [--audit-sink <url>] [--dry-run] [--no-interactive] [--approval-timeout <duration>]")
	fmt.Println("  agentfence explain --policy <file> --tool <name> [--args <json>] [--output text|json]")
	fmt.Println("  agentfence policy  test     --policy <file> --tests <yaml> [--output text|json] [--verbose]")
	fmt.Println("  agentfence policy  validate --policy <file>")
	fmt.Println("  agentfence proxy   --policy <file> [--audit-log <file>] [--log-format text|json] [--metrics-listen <addr>] [--tamper-evident] [--sign-key <file>] [--audit-max-size <bytes>] [--audit-max-age <dur>] [--audit-keep <n>] [--audit-fsync] [--audit-sink <url>] [--passthrough] [--no-interactive] [--approval-timeout <duration>] [--debug] -- <command> [args...]")
	fmt.Println("  agentfence proxy-http --upstream <url> --policy <file> [--listen <addr>] [--log-format text|json] [--metrics-listen <addr>] [--on-batch reject|evaluate] [--on-unparsed forward|reject] [--auth-token <token>] [--audit-log <file>] [--tamper-evident] [--sign-key <file>] [--audit-max-size <bytes>] [--audit-max-age <dur>] [--audit-keep <n>] [--audit-fsync] [--audit-sink <url>] [--passthrough] [--no-interactive] [--approval-timeout <duration>] [--debug]")
	fmt.Println("  agentfence validate --policy <file>")
	fmt.Println("  agentfence audit   verify    --log <file> [--output text|json] [--pubkey <file>] [--anchor <file>] [--anchor-pubkey <file>]")
	fmt.Println("  agentfence audit   summarize --log <file> [--output text|json] [--top N]")
	fmt.Println("  agentfence audit   export    --log <file> [--format weaver-trace]")
	fmt.Println("  agentfence audit   keygen    --private <file> --public <file>")
	fmt.Println("  agentfence audit   anchor    --log <file> [--out <file>] [--sign-key <file>]")
	fmt.Println("  agentfence version")
	fmt.Println("  agentfence demo")
	fmt.Println("  agentfence init    [--pack filesystem,github,shell]")
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

// runAuditSubcmd dispatches audit sub-commands: verify, summarize, export,
// keygen, anchor.
func runAuditSubcmd(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("audit requires a subcommand: verify, summarize, export, keygen, anchor")
	}
	if isHelpArg(args[0]) {
		fmt.Println("Usage:")
		fmt.Println("  agentfence audit   verify    --log <file> [--output text|json] [--pubkey <file>] [--anchor <file>] [--anchor-pubkey <file>]")
		fmt.Println("  agentfence audit   summarize --log <file> [--output text|json] [--top N]")
		fmt.Println("  agentfence audit   export    --log <file> [--format weaver-trace]")
		fmt.Println("  agentfence audit   keygen    --private <file> --public <file>")
		fmt.Println("  agentfence audit   anchor    --log <file> [--out <file>] [--sign-key <file>]")
		return nil
	}
	switch args[0] {
	case "verify":
		return runAuditVerify(args[1:])
	case "summarize":
		return runAuditSummarize(args[1:])
	case "export":
		return runAuditExport(args[1:])
	case "keygen":
		return runAuditKeygen(args[1:])
	case "anchor":
		return runAuditAnchor(args[1:])
	default:
		return fmt.Errorf("unknown audit subcommand %q; valid: verify, summarize, export, keygen, anchor", args[0])
	}
}

// runAuditKeygen generates an Ed25519 key pair for audit-event signing.
func runAuditKeygen(args []string) error {
	fs := flag.NewFlagSet("audit keygen", flag.ContinueOnError)
	privPath := fs.String("private", "", "Output path for the Ed25519 private key (PEM); required")
	pubPath := fs.String("public", "", "Output path for the Ed25519 public key (PEM); required")
	if err := fs.Parse(args); err != nil {
		return handleFlagParseErr(err)
	}
	if *privPath == "" || *pubPath == "" {
		return errors.New("--private and --public are required")
	}
	pub, priv, err := audit.GenerateKeyPair()
	if err != nil {
		return fmt.Errorf("audit keygen: %w", err)
	}
	if err := audit.WriteKeyPairFiles(*privPath, *pubPath, pub, priv); err != nil {
		return err
	}
	fmt.Printf("wrote private key %s (0600) and public key %s\n", *privPath, *pubPath)
	fmt.Println("sign with: agentfence check ... --sign-key " + *privPath)
	fmt.Println("verify with: agentfence audit verify --log <file> --pubkey " + *pubPath)
	return nil
}

// runAuditAnchor computes a publishable anchor over a tamper-evident log so a
// third party can later detect silent whole-log deletion or truncation.
func runAuditAnchor(args []string) error {
	fs := flag.NewFlagSet("audit anchor", flag.ContinueOnError)
	logPath := fs.String("log", "", "Path to the tamper-evident audit log to anchor; required")
	out := fs.String("out", "", "Write the anchor JSON to this file (default: stdout)")
	signKey := fs.String("sign-key", "", "Optional Ed25519 private key (PEM) to sign the anchor")
	if err := fs.Parse(args); err != nil {
		return handleFlagParseErr(err)
	}
	if *logPath == "" {
		return errors.New("--log is required")
	}

	var signer *audit.Signer
	if *signKey != "" {
		priv, err := audit.LoadPrivateKey(*signKey)
		if err != nil {
			return err
		}
		signer, err = audit.NewSigner(priv)
		if err != nil {
			return err
		}
	}

	f, err := os.Open(*logPath)
	if err != nil {
		return err
	}
	defer f.Close()

	anchor, err := audit.ComputeAnchor(f, signer)
	switch {
	case errors.Is(err, audit.ErrNoChain):
		return fmt.Errorf("audit anchor: %q is not tamper-evident; re-run with --tamper-evident to chain it before anchoring", *logPath)
	case err != nil:
		return fmt.Errorf("audit anchor: %w", err)
	}

	b, err := json.MarshalIndent(anchor, "", "  ")
	if err != nil {
		return fmt.Errorf("audit anchor: json marshal: %w", err)
	}
	if *out == "" {
		fmt.Printf("%s\n", b)
		fmt.Fprintf(os.Stderr, "anchored %d event(s); commit this anchor somewhere you do not control to detect later deletion\n", anchor.EventCount)
		return nil
	}
	if err := os.WriteFile(*out, append(b, '\n'), 0o644); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "wrote anchor for %d event(s) to %s\n", anchor.EventCount, *out)
	return nil
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

	// stdout carries the JSONL trace stream, so the count goes to stderr to
	// avoid corrupting it — mirroring how `verify`/`summarize` report results.
	n, err := interop.ExportTraces(f, os.Stdout)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "exported %d event(s)\n", n)
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

// auditVerifyReport is the combined result of `audit verify --output json`. The
// chain check always runs; signatures and anchor are present only when their
// respective flags were given. Each sub-result carries a stable status enum so
// CI and monitoring can act on integrity without parsing prose.
type auditVerifyReport struct {
	Chain      auditChainResult      `json:"chain"`
	Signatures *auditSignatureResult `json:"signatures,omitempty"`
	Anchor     *auditAnchorResult    `json:"anchor,omitempty"`
}

// auditChainResult reports the hash-chain check. Status is one of: ok, no_chain,
// partial, corrupt, failed, error (the last covers I/O failures and otherwise
// unclassified verification errors, so the JSON status is never empty).
type auditChainResult struct {
	Status          string `json:"status"`
	Events          int    `json:"events"`
	ChainStartEvent int    `json:"chain_start_event,omitempty"`
	BadEvent        int    `json:"bad_event,omitempty"`
	Detail          string `json:"detail,omitempty"`
}

// auditSignatureResult reports Ed25519 signature verification. Status is one of:
// ok, no_signatures, error.
type auditSignatureResult struct {
	Status   string `json:"status"`
	Verified int    `json:"verified"`
	Unsigned int    `json:"unsigned"`
	Detail   string `json:"detail,omitempty"`

	// reported records whether a SIGNATURES count line was produced, so the
	// text presenter matches the historical behaviour of staying silent when
	// verification itself errored before any counts were available.
	reported bool
}

// auditAnchorResult reports anchor truncation detection. Status is one of: ok,
// truncated, error. SignatureStatus is one of: verified, unsigned,
// signed_unverified, not_checked, error.
type auditAnchorResult struct {
	Status          string `json:"status,omitempty"`
	AnchoredSeq     uint64 `json:"anchored_seq"`
	SignatureStatus string `json:"signature_status,omitempty"`
	Detail          string `json:"detail,omitempty"`
}

// runAuditVerify checks the tamper-evident hash chain of a JSONL audit log and,
// optionally, the Ed25519 signatures (--pubkey) and presence of a previously
// published anchor (--anchor). With --output json it emits a single combined
// result object; exit-code semantics are identical in both modes.
func runAuditVerify(args []string) error {
	fs := flag.NewFlagSet("audit verify", flag.ContinueOnError)
	logPath := fs.String("log", "", "Path to audit JSONL log to verify")
	pubKeyPath := fs.String("pubkey", "", "Optional Ed25519 public key (PEM) to verify event signatures")
	anchorPath := fs.String("anchor", "", "Optional anchor JSON (from 'audit anchor') to confirm the log has not been truncated")
	anchorPubKeyPath := fs.String("anchor-pubkey", "", "Optional Ed25519 public key (PEM) to authenticate a signed anchor (from 'audit anchor --sign-key')")
	outputMode := fs.String("output", "text", "Output mode: text, json")
	if err := fs.Parse(args); err != nil {
		return handleFlagParseErr(err)
	}
	if *logPath == "" {
		return errors.New("--log is required")
	}
	switch *outputMode {
	case "text", "json":
	default:
		return fmt.Errorf("unknown --output mode %q; valid values: text, json", *outputMode)
	}
	jsonOut := *outputMode == "json"

	report := auditVerifyReport{}
	// finish emits the JSON object once (in json mode) and returns the gating
	// error so the exit code is identical to text mode.
	finish := func(gateErr error) error {
		if jsonOut {
			b, err := json.MarshalIndent(report, "", "  ")
			if err != nil {
				return fmt.Errorf("audit verify: json marshal: %w", err)
			}
			fmt.Printf("%s\n", b)
		}
		return gateErr
	}

	chain, err := computeChainResult(*logPath)
	report.Chain = chain
	if !jsonOut {
		chain.printText()
	}
	if err != nil {
		return finish(err)
	}

	if *pubKeyPath != "" {
		sig, err := computeSignatureResult(*logPath, *pubKeyPath)
		report.Signatures = &sig
		if !jsonOut {
			sig.printText()
		}
		if err != nil {
			return finish(err)
		}
	}

	if *anchorPath != "" {
		anc, err := computeAnchorResult(*logPath, *anchorPath, *anchorPubKeyPath)
		report.Anchor = &anc
		if !jsonOut {
			anc.printText()
		}
		if err != nil {
			return finish(err)
		}
	}

	return finish(nil)
}

// computeChainResult runs the hash-chain check and maps it onto a structured
// result plus the gating error (nil for ok / no_chain, non-nil otherwise).
func computeChainResult(logPath string) (auditChainResult, error) {
	f, err := os.Open(logPath)
	if err != nil {
		return auditChainResult{Status: "error", Detail: err.Error()}, err
	}
	defer f.Close()

	n, err := audit.VerifyChain(f)
	res := auditChainResult{Events: n}
	switch {
	case err == nil:
		res.Status = "ok"
		return res, nil
	case errors.Is(err, audit.ErrNoChain):
		res.Status = "no_chain"
		res.Detail = err.Error()
		return res, nil
	case errors.Is(err, audit.ErrPartialChain):
		var pe *audit.PartialChainError
		if errors.As(err, &pe) {
			res.Status = "partial"
			res.Events = pe.Total
			res.ChainStartEvent = pe.ChainStartEvent
			res.Detail = pe.Error()
			return res, fmt.Errorf("audit verify: %s", pe.Error())
		}
		res.Status = "error"
		res.Detail = err.Error()
		return res, fmt.Errorf("audit verify: %w", err)
	default:
		var ve *audit.VerifyError
		if errors.As(err, &ve) {
			// Distinguish a damaged/unreadable line (corrupt input) from a
			// genuine integrity break (a rewritten or truncated chain): they
			// point an investigator at very different causes.
			res.BadEvent = ve.EventNumber
			if ve.Malformed {
				res.Status = "corrupt"
			} else {
				res.Status = "failed"
			}
			res.Detail = ve.Error()
			return res, fmt.Errorf("audit verify: %s", ve.Error())
		}
		res.Status = "error"
		res.Detail = err.Error()
		return res, fmt.Errorf("audit verify: %w", err)
	}
}

// printText reproduces the historical one-line chain status output.
func (c auditChainResult) printText() {
	switch c.Status {
	case "ok":
		fmt.Printf("OK: %d event(s) verified\n", c.Events)
	case "no_chain":
		fmt.Fprintf(os.Stderr, "AgentFence: warning: %s; cannot verify integrity\n", c.Detail)
		fmt.Printf("PARSED: %d event(s); chain absent\n", c.Events)
	case "partial":
		fmt.Printf("PARTIAL: %d event(s); chain starts at event %d; events 1..%d are not integrity-protected\n", c.Events, c.ChainStartEvent, c.ChainStartEvent-1)
	case "corrupt":
		fmt.Printf("CORRUPT: unreadable event at position %d; the file is damaged or is not an audit log\n", c.BadEvent)
	case "failed":
		fmt.Printf("FAILED: integrity check failed at event %d (possible tampering)\n", c.BadEvent)
	}
}

// computeSignatureResult verifies Ed25519 signatures. A non-empty log with no
// verifiable signatures is a failure, since the operator explicitly asked for
// signature verification.
func computeSignatureResult(logPath, pubKeyPath string) (auditSignatureResult, error) {
	pub, err := audit.LoadPublicKey(pubKeyPath)
	if err != nil {
		return auditSignatureResult{Status: "error", Detail: err.Error()}, err
	}
	f, err := os.Open(logPath)
	if err != nil {
		return auditSignatureResult{Status: "error", Detail: err.Error()}, err
	}
	defer f.Close()

	verified, unsigned, err := audit.VerifySignatures(f, pub)
	if err != nil {
		var ve *audit.VerifyError
		if errors.As(err, &ve) {
			return auditSignatureResult{Status: "error", Detail: ve.Error()}, fmt.Errorf("audit verify: signature: %s", ve.Error())
		}
		return auditSignatureResult{Status: "error", Detail: err.Error()}, fmt.Errorf("audit verify: signature: %w", err)
	}
	res := auditSignatureResult{Status: "ok", Verified: verified, Unsigned: unsigned, reported: true}
	if verified == 0 && unsigned > 0 {
		res.Status = "no_signatures"
		res.Detail = "no events were signed by the given key"
		return res, fmt.Errorf("audit verify: no events were signed by the given key")
	}
	return res, nil
}

// printText reproduces the historical SIGNATURES status line. It stays silent
// when verification errored before any counts were available.
func (s auditSignatureResult) printText() {
	if !s.reported {
		return
	}
	fmt.Printf("SIGNATURES: %d verified, %d unsigned\n", s.Verified, s.Unsigned)
}

// computeAnchorResult confirms the log still contains the anchored event and,
// when an anchor public key is supplied, that the anchor itself is
// authentically signed — truncation detection is only trustworthy if the
// anchor we compare against was not itself swapped for one naming an earlier
// event. The anchor key is separate from the event-signing key (--pubkey): a
// log may sign its events, its anchor, both, or neither, with distinct keys.
func computeAnchorResult(logPath, anchorPath, anchorPubKeyPath string) (auditAnchorResult, error) {
	ab, err := os.ReadFile(anchorPath)
	if err != nil {
		return auditAnchorResult{Status: "error", Detail: err.Error()}, err
	}
	var anchor audit.Anchor
	if err := json.Unmarshal(ab, &anchor); err != nil {
		wrapped := fmt.Errorf("audit verify: parse anchor %q: %w", anchorPath, err)
		return auditAnchorResult{Status: "error", Detail: wrapped.Error()}, wrapped
	}
	res := auditAnchorResult{AnchoredSeq: anchor.LastSeq}

	if anchorPubKeyPath != "" {
		pub, err := audit.LoadPublicKey(anchorPubKeyPath)
		if err != nil {
			res.SignatureStatus = "error"
			return res, err
		}
		switch err := audit.VerifyAnchorSignature(anchor, pub); {
		case err == nil:
			res.SignatureStatus = "verified"
		case errors.Is(err, audit.ErrNoSignature):
			res.SignatureStatus = "unsigned"
		default:
			res.SignatureStatus = "error"
			return res, fmt.Errorf("audit verify: anchor signature: %w", err)
		}
	} else if anchor.Signature != "" {
		res.SignatureStatus = "signed_unverified"
	} else {
		res.SignatureStatus = "not_checked"
	}

	f, err := os.Open(logPath)
	if err != nil {
		return res, err
	}
	defer f.Close()

	switch err := audit.VerifyAgainstAnchor(f, anchor); {
	case err == nil:
		res.Status = "ok"
		return res, nil
	case errors.Is(err, audit.ErrAnchorTruncated):
		res.Status = "truncated"
		res.Detail = err.Error()
		return res, fmt.Errorf("audit verify: %w", err)
	default:
		res.Status = "error"
		var ve *audit.VerifyError
		if errors.As(err, &ve) {
			res.Detail = ve.Error()
			return res, fmt.Errorf("audit verify: anchor: %s", ve.Error())
		}
		res.Detail = err.Error()
		return res, fmt.Errorf("audit verify: anchor: %w", err)
	}
}

// printText reproduces the historical anchor status output, including the
// stderr warnings for an unsigned or unverified-signature anchor.
func (a auditAnchorResult) printText() {
	switch a.SignatureStatus {
	case "verified":
		fmt.Println("ANCHOR SIGNATURE: verified")
	case "unsigned":
		fmt.Fprintln(os.Stderr, "AgentFence: warning: anchor is unsigned; its origin cannot be authenticated")
	case "signed_unverified":
		fmt.Fprintln(os.Stderr, "AgentFence: warning: anchor is signed but no --anchor-pubkey was given; its signature was not verified")
	}
	switch a.Status {
	case "ok":
		fmt.Printf("ANCHOR: log still contains anchored event seq=%d\n", a.AnchoredSeq)
	case "truncated":
		fmt.Printf("ANCHOR: FAILED — anchored event seq=%d is missing\n", a.AnchoredSeq)
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
// serveMetrics starts a Prometheus metrics endpoint on addr exposing counters
// and returns a stop function. The endpoint is local and operator-chosen:
// nothing is sent anywhere AgentFence picks, consistent with the no-telemetry
// posture. The returned function (typically deferred) shuts the endpoint down
// and prints a final text summary of the counters to stderr.
func serveMetrics(addr string, counters *metrics.Counters, logger *slog.Logger) func() {
	srv := &http.Server{Handler: metrics.ServeMux(counters)}
	// Bind synchronously so an unusable address (in use, no permission, bad
	// host) is reported at startup rather than silently in a goroutine. A bind
	// failure leaves the proxy running without the endpoint — metrics are
	// best-effort observability and must not take the gate down.
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		logger.Error("metrics endpoint disabled: cannot bind", "addr", addr, "err", err)
		return func() {}
	}
	go func() {
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("metrics endpoint failed", "addr", addr, "err", err)
		}
	}()
	logger.Info("metrics endpoint listening", "addr", addr, "path", "/metrics")
	return func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
		_ = counters.Snapshot().FormatText(os.Stderr)
	}
}

func runProxy(args []string) error {
	fs := flag.NewFlagSet("proxy", flag.ContinueOnError)
	policyPath := fs.String("policy", "", "Path to policy YAML (required unless --passthrough)")
	auditLogPath := fs.String("audit-log", "", "Optional path to write audit JSONL")
	tamperEvident := fs.Bool("tamper-evident", false, "Write a hash-chained audit log (use with --audit-log; verify with 'agentfence audit verify')")
	passthrough := fs.Bool("passthrough", false, "Forward every message without policy evaluation (skeleton mode; useful for validating the relay)")
	noInteractive := fs.Bool("no-interactive", false, "Auto-deny every ask decision instead of prompting the operator on the TTY")
	approvalTimeout := fs.Duration("approval-timeout", 0, "Maximum time to wait for an interactive ask response (e.g. 30s, 2m). 0 waits indefinitely")
	debug := fs.Bool("debug", false, "Log every forwarded message to stderr")
	logFormat := fs.String("log-format", "text", "Operational log format for stderr diagnostics: text or json (distinct from the audit log)")
	metricsListen := fs.String("metrics-listen", "", "Expose Prometheus decision/latency/error metrics at /metrics on this address (e.g. 127.0.0.1:9090); empty disables it")
	signKey := fs.String("sign-key", "", "Path to an Ed25519 private key (PEM) to sign each audit event; verify with 'agentfence audit verify --pubkey'")
	auditMaxSize := fs.Int64("audit-max-size", 0, "Rotate the audit log once it reaches this many bytes (0 = no size rotation; requires --audit-log)")
	auditMaxAge := fs.Duration("audit-max-age", 0, "Rotate the audit log once it has been open this long, e.g. 24h (0 = no age rotation; requires --audit-log)")
	auditKeep := fs.Int("audit-keep", 0, "Number of rotated audit segments to retain (0 = keep all)")
	auditFsync := fs.Bool("audit-fsync", false, "fsync the audit log to disk after every event so a decision survives a crash or power loss (slower; requires --audit-log)")
	var auditSinks stringSliceFlag
	fs.Var(&auditSinks, "audit-sink", "Ship audit events to an external sink; repeatable. Schemes: http(s)://…, syslog://host:port, syslog+tcp://host:port")
	if err := fs.Parse(args); err != nil {
		return handleFlagParseErr(err)
	}

	logFmt, err := oplog.ParseFormat(*logFormat)
	if err != nil {
		return err
	}

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

	auditOut, closeAudit, auditOptions, err := openAuditOutput(auditConfig{
		path:          *auditLogPath,
		tamperEvident: *tamperEvident,
		signKeyPath:   *signKey,
		maxSizeBytes:  *auditMaxSize,
		maxAge:        *auditMaxAge,
		keep:          *auditKeep,
		sinkSpecs:     auditSinks,
		fsync:         *auditFsync,
		noFileWriter:  io.Discard,
	})
	if err != nil {
		return err
	}
	defer closeAudit()
	aw := audit.NewWriterOptions(auditOut, auditOptions)

	// In passthrough mode the engine never runs, so no approver is needed.
	var approver proxy.Approver = proxy.DenyAllApprover{}
	if !*passthrough {
		a, cleanup, err := newProxyApprover(*noInteractive)
		if err != nil {
			return err
		}
		defer cleanup()
		approver = a
	}

	logger := oplog.New(os.Stderr, logFmt, *debug)

	opts := proxy.Options{
		Engine:          eng,
		AuditWriter:     aw,
		Approver:        approver,
		ApprovalTimeout: *approvalTimeout,
		NoInteractive:   *noInteractive,
		Passthrough:     *passthrough,
		Debug:           *debug,
		Logger:          logger,
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	if *metricsListen != "" {
		counters := metrics.New()
		opts.Metrics = counters
		stopMetrics := serveMetrics(*metricsListen, counters, logger)
		defer stopMetrics()
	}

	// Return the proxy.Run error unchanged. When the downstream MCP server
	// exits non-zero, it is an *exec.ExitError; main() detects that and
	// exits with the same code. Returning here (instead of calling
	// os.Exit inside runProxy) lets the deferred closeAudit() flush and
	// close the audit log before the process exits.
	return proxy.Run(ctx, cmdName, cmdArgs, opts)
}

// runProxyHTTP launches the MCP streamable-HTTP proxy in front of a remote MCP
// server. Unlike the stdio proxy it takes no downstream command; it listens on
// --listen and forwards gated tools/call requests to --upstream:
//
//	agentfence proxy-http --policy policy.yaml --upstream https://mcp.example.com/mcp
//
// See docs/integration-guide.md and docs/threat-model.md for the HTTP surface.
func runProxyHTTP(args []string) error {
	fs := flag.NewFlagSet("proxy-http", flag.ContinueOnError)
	policyPath := fs.String("policy", "", "Path to policy YAML (required unless --passthrough)")
	upstream := fs.String("upstream", "", "Upstream MCP server base URL (required), e.g. https://mcp.example.com/mcp")
	listen := fs.String("listen", "127.0.0.1:8787", "Local address to listen on")
	onBatch := fs.String("on-batch", "reject", "JSON-RPC batch (array) body handling: reject (fail-closed default) or evaluate (gate every member, forward only if all allowed)")
	onUnparsed := fs.String("on-unparsed", "forward", "Handling for POST bodies that are not valid JSON-RPC: forward (default) or reject")
	authToken := fs.String("auth-token", "", "Require this bearer token on every request (Authorization: Bearer <token>). Falls back to $AGENTFENCE_PROXY_AUTH_TOKEN; empty disables auth")
	auditLogPath := fs.String("audit-log", "", "Optional path to write audit JSONL")
	tamperEvident := fs.Bool("tamper-evident", false, "Write a hash-chained audit log (use with --audit-log; verify with 'agentfence audit verify')")
	passthrough := fs.Bool("passthrough", false, "Forward every request without policy evaluation (useful for validating the relay)")
	noInteractive := fs.Bool("no-interactive", false, "Auto-deny every ask decision instead of prompting the operator on the TTY")
	approvalTimeout := fs.Duration("approval-timeout", 0, "Maximum time to wait for an interactive ask response (e.g. 30s, 2m). 0 waits indefinitely")
	debug := fs.Bool("debug", false, "Log every proxied request to stderr")
	logFormat := fs.String("log-format", "text", "Operational log format for stderr diagnostics: text or json (distinct from the audit log)")
	metricsListen := fs.String("metrics-listen", "", "Expose Prometheus decision/latency/error metrics at /metrics on this address (e.g. 127.0.0.1:9090); empty disables it")
	signKey := fs.String("sign-key", "", "Path to an Ed25519 private key (PEM) to sign each audit event; verify with 'agentfence audit verify --pubkey'")
	auditMaxSize := fs.Int64("audit-max-size", 0, "Rotate the audit log once it reaches this many bytes (0 = no size rotation; requires --audit-log)")
	auditMaxAge := fs.Duration("audit-max-age", 0, "Rotate the audit log once it has been open this long, e.g. 24h (0 = no age rotation; requires --audit-log)")
	auditKeep := fs.Int("audit-keep", 0, "Number of rotated audit segments to retain (0 = keep all)")
	auditFsync := fs.Bool("audit-fsync", false, "fsync the audit log to disk after every event so a decision survives a crash or power loss (slower; requires --audit-log)")
	var auditSinks stringSliceFlag
	fs.Var(&auditSinks, "audit-sink", "Ship audit events to an external sink; repeatable. Schemes: http(s)://…, syslog://host:port, syslog+tcp://host:port")
	if err := fs.Parse(args); err != nil {
		return handleFlagParseErr(err)
	}

	logFmt, err := oplog.ParseFormat(*logFormat)
	if err != nil {
		return err
	}

	if *upstream == "" {
		return errors.New("--upstream is required")
	}
	upstreamURL, err := url.Parse(*upstream)
	if err != nil {
		return fmt.Errorf("--upstream: %w", err)
	}
	if upstreamURL.Scheme == "" || upstreamURL.Host == "" {
		return fmt.Errorf("--upstream %q must be an absolute URL with scheme and host", *upstream)
	}

	batchPolicy, err := parseBatchPolicy(*onBatch)
	if err != nil {
		return err
	}
	unparsedPolicy, err := parseUnparsedPolicy(*onUnparsed)
	if err != nil {
		return err
	}

	authTok := *authToken
	if authTok == "" {
		authTok = os.Getenv("AGENTFENCE_PROXY_AUTH_TOKEN")
	}
	// Bind-address guardrail: an off-loopback listener with no authentication
	// exposes the gate to other clients. Warn rather than fail so deliberate
	// fronting (e.g. behind a TLS terminator) still works.
	if authTok == "" && !isLoopbackListen(*listen) {
		fmt.Fprintf(os.Stderr, "agentfence: warning: --listen %s is not loopback and no --auth-token/$AGENTFENCE_PROXY_AUTH_TOKEN is set; the policy proxy is reachable without authentication\n", *listen)
	}

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

	auditOut, closeAudit, auditOptions, err := openAuditOutput(auditConfig{
		path:          *auditLogPath,
		tamperEvident: *tamperEvident,
		signKeyPath:   *signKey,
		maxSizeBytes:  *auditMaxSize,
		maxAge:        *auditMaxAge,
		keep:          *auditKeep,
		sinkSpecs:     auditSinks,
		fsync:         *auditFsync,
		noFileWriter:  io.Discard,
	})
	if err != nil {
		return err
	}
	defer closeAudit()
	aw := audit.NewWriterOptions(auditOut, auditOptions)

	// In passthrough mode the engine never runs, so no approver is needed.
	var approver httpproxy.Approver = httpproxy.DenyAllApprover{}
	if !*passthrough {
		a, cleanup, err := newProxyApprover(*noInteractive)
		if err != nil {
			return err
		}
		defer cleanup()
		approver = a
	}

	logger := oplog.New(os.Stderr, logFmt, *debug)

	opts := httpproxy.Options{
		Engine:          eng,
		AuditWriter:     aw,
		Approver:        approver,
		ApprovalTimeout: *approvalTimeout,
		NoInteractive:   *noInteractive,
		Upstream:        upstreamURL,
		Passthrough:     *passthrough,
		Debug:           *debug,
		Logger:          logger,
		OnBatch:         batchPolicy,
		OnUnparsed:      unparsedPolicy,
		AuthToken:       authTok,
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	if *metricsListen != "" {
		counters := metrics.New()
		opts.Metrics = counters
		stopMetrics := serveMetrics(*metricsListen, counters, logger)
		defer stopMetrics()
	}

	return httpproxy.Serve(ctx, *listen, opts)
}

// parseBatchPolicy maps the --on-batch flag value to an httpproxy.BatchPolicy.
func parseBatchPolicy(s string) (httpproxy.BatchPolicy, error) {
	switch s {
	case string(httpproxy.BatchReject):
		return httpproxy.BatchReject, nil
	case string(httpproxy.BatchEvaluate):
		return httpproxy.BatchEvaluate, nil
	default:
		return "", fmt.Errorf("--on-batch must be %q or %q, got %q", httpproxy.BatchReject, httpproxy.BatchEvaluate, s)
	}
}

// parseUnparsedPolicy maps the --on-unparsed flag value to an
// httpproxy.UnparsedPolicy.
func parseUnparsedPolicy(s string) (httpproxy.UnparsedPolicy, error) {
	switch s {
	case string(httpproxy.UnparsedForward):
		return httpproxy.UnparsedForward, nil
	case string(httpproxy.UnparsedReject):
		return httpproxy.UnparsedReject, nil
	default:
		return "", fmt.Errorf("--on-unparsed must be %q or %q, got %q", httpproxy.UnparsedForward, httpproxy.UnparsedReject, s)
	}
}

// isLoopbackListen reports whether a listen address binds only to loopback. A
// host-less address (":8787") or a wildcard ("0.0.0.0", "::") is NOT loopback;
// an explicit loopback IP or "localhost" is. Used by the bind-address guardrail.
func isLoopbackListen(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		// Unparseable host:port — be conservative so the guardrail still fires.
		host = addr
	}
	switch host {
	case "":
		return false // ":8787" binds all interfaces
	case "localhost":
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

// stringSliceFlag is a repeatable string flag (e.g. --audit-sink a --audit-sink b).
type stringSliceFlag []string

func (s *stringSliceFlag) String() string { return strings.Join(*s, ",") }

func (s *stringSliceFlag) Set(v string) error {
	*s = append(*s, v)
	return nil
}

// auditConfig collects the audit-output flags shared by check, proxy, and
// proxy-http. noFileWriter is the destination used when path is empty: os.Stdout
// for check's text mode, io.Discard otherwise (the proxies MUST NOT interleave
// audit JSONL with the agent's JSON-RPC stdout).
type auditConfig struct {
	path          string
	tamperEvident bool
	signKeyPath   string
	maxSizeBytes  int64
	maxAge        time.Duration
	keep          int
	sinkSpecs     []string
	fsync         bool
	noFileWriter  io.Writer
}

// openAuditOutput returns the audit destination Writer, a close func, and the
// writer options assembled from cfg (tamper-evident chaining, Ed25519 signing,
// rotation, and external sinks).
//
// New files are created with 0o600 (owner-read/write) so audit events —
// which can contain redacted-but-still-sensitive tool arguments — do not
// inherit a permissive umask. Pre-existing files are opened in append mode
// without altering their permissions, on the assumption that the operator
// chose those bits deliberately.
//
// The returned close func tears everything down in the right order — flush and
// close the file/rotator first, then drain and close any external sink — so a
// sink never loses buffered events written just before shutdown.
func openAuditOutput(cfg auditConfig) (io.Writer, func(), audit.Options, error) {
	options := audit.Options{TamperEvident: cfg.tamperEvident, Fsync: cfg.fsync}

	var closers []func()
	closeAll := func() {
		for i := len(closers) - 1; i >= 0; i-- {
			closers[i]()
		}
	}
	fail := func(err error) (io.Writer, func(), audit.Options, error) {
		closeAll()
		return nil, nil, audit.Options{}, err
	}

	// Signing is independent of the destination.
	if cfg.signKeyPath != "" {
		priv, err := audit.LoadPrivateKey(cfg.signKeyPath)
		if err != nil {
			return fail(err)
		}
		signer, err := audit.NewSigner(priv)
		if err != nil {
			return fail(err)
		}
		options.Signer = signer
	}

	// External sinks are also independent of the destination, so events can be
	// shipped even when no local file is written.
	sink, err := audit.ParseSinks(cfg.sinkSpecs, os.Stderr)
	if err != nil {
		return fail(err)
	}
	if sink != nil {
		options.Sink = sink
		closers = append(closers, func() { _ = sink.Close() })
	}

	rotationRequested := cfg.maxSizeBytes > 0 || cfg.maxAge > 0

	// --audit-keep only prunes rotated segments, so it does nothing unless a
	// size or age threshold actually triggers rotation. Warn rather than fail,
	// so a keep value paired with a not-yet-set threshold is not a hard error.
	if cfg.keep > 0 && !rotationRequested {
		fmt.Fprintln(os.Stderr, "AgentFence: warning: --audit-keep has no effect without --audit-max-size or --audit-max-age")
	}

	// fsync only has a destination to flush when a file (or rotated file) backs
	// the log. Against stdout/discard it is disabled outright: there is nothing
	// meaningful to flush, and Sync() on a TTY or pipe stdout (check's text
	// mode) returns EINVAL, which would fail the run. Warn rather than imply a
	// durability guarantee that isn't there.
	if cfg.fsync && cfg.path == "" {
		options.Fsync = false
		fmt.Fprintln(os.Stderr, "AgentFence: warning: --audit-fsync has no effect without --audit-log")
	}

	if cfg.path == "" {
		if rotationRequested {
			return fail(errors.New("audit: --audit-max-size/--audit-max-age require --audit-log"))
		}
		if cfg.tamperEvident {
			if cfg.noFileWriter == nil || cfg.noFileWriter == io.Discard {
				fmt.Fprintln(os.Stderr, "AgentFence: warning: --tamper-evident without --audit-log discards audit events; nothing to verify.")
			} else {
				fmt.Fprintln(os.Stderr, "AgentFence: warning: --tamper-evident without --audit-log produces a chain interleaved with other output; verification will not be reliable.")
			}
		}
		dest := cfg.noFileWriter
		if dest == nil {
			dest = io.Discard
		}
		return dest, closeAll, options, nil
	}

	if rotationRequested {
		rot, err := audit.NewRotator(audit.RotationConfig{
			Path:         cfg.path,
			MaxSizeBytes: cfg.maxSizeBytes,
			MaxAge:       cfg.maxAge,
			Keep:         cfg.keep,
		})
		if err != nil {
			return fail(err)
		}
		closers = append(closers, func() {
			// On shutdown, force a final flush to stable storage before closing
			// so a --audit-fsync run loses nothing to a signal-driven exit.
			if cfg.fsync {
				_ = rot.Sync()
			}
			_ = rot.Close()
		})
		if cfg.tamperEvident {
			lastHash, eventCount, firstChained, err := rot.ResumeState()
			if err != nil {
				return fail(fmt.Errorf("audit: existing log chain: %w", err))
			}
			if refuseErr := refuseMixedChain(cfg.path, eventCount, firstChained); refuseErr != nil {
				return fail(refuseErr)
			}
			options.InitialPrevHash = lastHash
		}
		options.Rotator = rot
		return rot, closeAll, options, nil
	}

	flags := os.O_WRONLY | os.O_CREATE | os.O_APPEND
	if cfg.tamperEvident {
		flags = os.O_RDWR | os.O_CREATE | os.O_APPEND
	}
	f, err := os.OpenFile(cfg.path, flags, 0o600)
	if err != nil {
		return fail(err)
	}
	closers = append(closers, func() {
		// Mirror the rotator path: a final fsync on shutdown guarantees a
		// --audit-fsync log is durable even if the process is terminated.
		if cfg.fsync {
			_ = f.Sync()
		}
		_ = f.Close()
	})
	if cfg.tamperEvident {
		if _, err := f.Seek(0, io.SeekStart); err != nil {
			return fail(err)
		}
		lastHash, eventCount, firstChained, err := audit.LastChainState(f)
		if err != nil {
			return fail(fmt.Errorf("audit: existing log chain: %w", err))
		}
		if refuseErr := refuseMixedChain(cfg.path, eventCount, firstChained); refuseErr != nil {
			return fail(refuseErr)
		}
		options.InitialPrevHash = lastHash
		if _, err := f.Seek(0, io.SeekEnd); err != nil {
			return fail(err)
		}
	}
	return f, closeAll, options, nil
}

// refuseMixedChain rejects enabling --tamper-evident on an existing log that is
// not already fully chained from event 1, which would otherwise produce a mixed
// log whose prefix is not integrity-protected. Two cases are rejected:
//
//  1. fully unchained log (firstChained == 0): appending would produce a mixed
//     log whose prefix is not integrity-protected.
//  2. partial-chain log (firstChained > 1): a previous run already produced the
//     mixed state; continuing the chain perpetuates the unprotected prefix.
//
// In both cases `audit verify` would later surface the file as PARTIAL; failing
// early at write time is the symmetric defence.
func refuseMixedChain(path string, eventCount, firstChained int) error {
	if eventCount == 0 || firstChained == 1 {
		return nil
	}
	if firstChained == 0 {
		return fmt.Errorf("audit: cannot enable --tamper-evident on existing unchained log %q (%d unchained event(s)); use a new file or convert the log first", path, eventCount)
	}
	return fmt.Errorf("audit: cannot enable --tamper-evident on existing partial-chain log %q (chain starts at event %d of %d; events 1..%d are not integrity-protected); use a new file or convert the log first", path, firstChained, eventCount, firstChained-1)
}

// runPolicySubcmd dispatches policy sub-commands: test, validate.
func runPolicySubcmd(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("policy requires a subcommand: test, validate")
	}
	if isHelpArg(args[0]) {
		fmt.Println("Usage:")
		fmt.Println("  agentfence policy  test     --policy <file> --tests <yaml> [--output text|json] [--verbose]")
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

// policyTestCaseResult is one row of the `policy test --output json` report.
type policyTestCaseResult struct {
	ID     string          `json:"id"`
	Tool   string          `json:"tool"`
	Expect policy.Decision `json:"expect"`
	Got    policy.Decision `json:"got"`
	Pass   bool            `json:"pass"`
	Reason string          `json:"reason"`
}

// policyTestReport is the top-level shape emitted by `policy test --output json`.
// It mirrors the text PASS/FAIL output so CI can consume per-case results and a
// totals summary structurally.
type policyTestReport struct {
	Total  int                    `json:"total"`
	Passed int                    `json:"passed"`
	Failed int                    `json:"failed"`
	Cases  []policyTestCaseResult `json:"cases"`
}

// runPolicyTest evaluates a YAML fixture file against a policy and reports
// pass/fail. With --output json it emits a stable report instead of PASS/FAIL
// prose; either way it returns a non-zero exit (an error) when any case fails.
func runPolicyTest(args []string) error {
	fs := flag.NewFlagSet("policy test", flag.ContinueOnError)
	policyPath := fs.String("policy", "", "Path to policy YAML")
	testsPath := fs.String("tests", "", "Path to test fixture YAML")
	outputMode := fs.String("output", "text", "Output mode: text, json")
	verbose := fs.Bool("verbose", false, "Print decision reason alongside each result (text mode only; JSON always includes the reason)")
	if err := fs.Parse(args); err != nil {
		return handleFlagParseErr(err)
	}
	if *policyPath == "" || *testsPath == "" {
		return errors.New("--policy and --tests are required")
	}
	switch *outputMode {
	case "text", "json":
	default:
		return fmt.Errorf("unknown --output mode %q; valid values: text, json", *outputMode)
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

	jsonOut := *outputMode == "json"
	report := policyTestReport{Cases: make([]policyTestCaseResult, 0, len(fixture.Tests))}
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
		pass := result.Decision == tc.Expect

		report.Total++
		if pass {
			report.Passed++
		} else {
			report.Failed++
		}

		if jsonOut {
			report.Cases = append(report.Cases, policyTestCaseResult{
				ID:     tc.ID,
				Tool:   tc.Tool,
				Expect: tc.Expect,
				Got:    result.Decision,
				Pass:   pass,
				Reason: result.Reason,
			})
			continue
		}

		// Text mode: keep the historical PASS/FAIL line shapes.
		if pass {
			if *verbose {
				fmt.Printf("PASS: %s (%s)\n", tc.ID, result.Reason)
			} else {
				fmt.Printf("PASS: %s\n", tc.ID)
			}
		} else {
			fmt.Printf("FAIL: %s (expected %s, got %s)\n", tc.ID, tc.Expect, result.Decision)
		}
	}

	if jsonOut {
		out, err := json.MarshalIndent(report, "", "  ")
		if err != nil {
			return fmt.Errorf("policy test: json marshal: %w", err)
		}
		fmt.Printf("%s\n", out)
	}

	if report.Failed > 0 {
		return fmt.Errorf("%d test(s) failed", report.Failed)
	}
	return nil
}
