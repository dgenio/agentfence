package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
)

func main() {
	var in reportInput
	var outputJSON, outputMarkdown string

	flag.StringVar(&in.DecisionsPath, "decisions", "", "Path to AgentFence check --output json decisions")
	flag.StringVar(&in.AuditPath, "audit", "", "Optional path to AgentFence audit JSONL used only for aggregate binding coverage")
	flag.StringVar(&in.AuditVerificationPath, "audit-verification", "", "Optional path to agentfence audit verify --output json")
	flag.StringVar(&in.PolicyTestsPath, "policy-tests", "", "Optional path to agentfence policy test --output json")
	flag.StringVar(&in.PolicyValidationStatus, "policy-validation-status", statusNotEvaluated, "Policy validation status: observed, failed, or not_evaluated")
	flag.StringVar(&in.Context, "context", "", "Optional source context such as owner/repo@commit")
	flag.StringVar(&outputJSON, "output-json", "", "Path to write the versioned machine-readable report")
	flag.StringVar(&outputMarkdown, "output-md", "", "Path to write the human-readable Markdown report")
	flag.Parse()

	if in.DecisionsPath == "" {
		fatal(errors.New("--decisions is required"))
	}
	if outputJSON == "" || outputMarkdown == "" {
		fatal(errors.New("--output-json and --output-md are required"))
	}

	report, err := buildReport(in)
	if err != nil {
		fatal(err)
	}
	if err := writeJSON(outputJSON, report); err != nil {
		fatal(err)
	}
	if err := writeMarkdown(outputMarkdown, report); err != nil {
		fatal(err)
	}
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "evidence-report:", err)
	os.Exit(1)
}
