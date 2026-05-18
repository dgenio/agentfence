package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/dgenio/agentfence/internal/audit"
	"github.com/dgenio/agentfence/internal/demo"
	"github.com/dgenio/agentfence/internal/engine"
	"github.com/dgenio/agentfence/internal/policy"
)

func main() {
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
	default:
		printUsage()
		err = fmt.Errorf("unknown command: %s", os.Args[1])
	}

	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func runCheck(args []string) error {
	fs := flag.NewFlagSet("check", flag.ContinueOnError)
	policyPath := fs.String("policy", "", "Path to policy YAML")
	callPath := fs.String("call", "", "Path to JSONL tool-call input")
	auditLogPath := fs.String("audit-log", "", "Optional path to write audit JSONL")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *policyPath == "" || *callPath == "" {
		return errors.New("--policy and --call are required")
	}

	p, err := policy.LoadFile(*policyPath)
	if err != nil {
		return err
	}

	eng, err := engine.New(p)
	if err != nil {
		return err
	}

	auditOut := os.Stdout
	if *auditLogPath != "" {
		f, err := os.Create(*auditLogPath)
		if err != nil {
			return err
		}
		defer f.Close()
		auditOut = f
	}

	aw := audit.NewWriter(auditOut)

	callsFile, err := os.Open(*callPath)
	if err != nil {
		return err
	}
	defer callsFile.Close()

	scanner := bufio.NewScanner(callsFile)
	line := 0
	for scanner.Scan() {
		line++
		call, err := policy.ParseToolCall(scanner.Bytes())
		if err != nil {
			return fmt.Errorf("parse call line %d: %w", line, err)
		}
		res, event := eng.Evaluate(call)
		fmt.Printf("%s %s -> %s (%s)\n", call.ID, call.Tool, res.Decision, res.Reason)
		if err := aw.Write(event); err != nil {
			return err
		}
	}

	if err := scanner.Err(); err != nil {
		return err
	}

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
	fmt.Println("  agentfence check --policy <file> --call <jsonl> [--audit-log <file>]")
	fmt.Println("  agentfence demo")
	fmt.Println("  agentfence init")
}
