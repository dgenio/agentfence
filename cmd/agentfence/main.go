package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime"

	"github.com/dgenio/agentfence/internal/audit"
	"github.com/dgenio/agentfence/internal/demo"
	"github.com/dgenio/agentfence/internal/engine"
	"github.com/dgenio/agentfence/internal/policy"
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
	case "check":
		err = runCheck(os.Args[2:])
	case "demo":
		err = demo.Run(os.Stdout)
	case "init":
		err = runInit()
	case "validate":
		err = runValidate(os.Args[2:])
	case "version":
		runVersion()
	default:
		printUsage()
		err = fmt.Errorf("unknown command: %s", os.Args[1])
	}

	if err != nil {
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

	aw := audit.NewWriter(auditOut)

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
				b, _ := json.Marshal(summary)
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
			b, _ := json.Marshal(summary)
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
	fmt.Println("  agentfence check --policy <file> --call <jsonl> [--audit-log <file>] [--output text|json|jsonl]")
	fmt.Println("  agentfence validate --policy <file>")
	fmt.Println("  agentfence version")
	fmt.Println("  agentfence demo")
	fmt.Println("  agentfence init")
}
