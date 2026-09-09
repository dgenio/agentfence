package main

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dgenio/agentfence/internal/audit"
	"github.com/dgenio/agentfence/internal/policy"
)

func TestRunCheckBindsEveryRepresentableDecision(t *testing.T) {
	dir := t.TempDir()
	policyFile := filepath.Join(dir, "policy.yaml")
	callFile := filepath.Join(dir, "calls.jsonl")
	auditFile := filepath.Join(dir, "audit.jsonl")

	writeTestFile(t, policyFile, []byte(`version: "0.1"
defaults:
  decision: deny
tools:
  demo.allow:
    decision: allow
  demo.deny:
    decision: deny
  demo.ask:
    decision: ask
`))
	writeTestFile(t, callFile, []byte("{\"id\":\"allow-1\",\"tool\":\"demo.allow\",\"arguments\":{\"value\":1}}\n"+
		"{\"id\":\"deny-1\",\"tool\":\"demo.deny\",\"arguments\":{\"value\":2}}\n"+
		"{\"id\":\"ask-1\",\"tool\":\"demo.ask\",\"arguments\":{\"value\":3}}\n"))

	if _, _, err := captureOutput(t, func() error {
		return runCheck([]string{
			"--policy", policyFile,
			"--call", callFile,
			"--audit-log", auditFile,
			"--output", "json",
			"--tamper-evident",
			"--dry-run",
		})
	}); err != nil {
		t.Fatalf("runCheck: %v", err)
	}

	events := readBoundCheckEvents(t, auditFile)
	if len(events) != 3 {
		t.Fatalf("events = %d, want 3", len(events))
	}
	wantDecisions := []policy.Decision{policy.DecisionAllow, policy.DecisionDeny, policy.DecisionAsk}
	for i, event := range events {
		if event.Decision != wantDecisions[i] {
			t.Fatalf("event %d decision = %q, want %q", i+1, event.Decision, wantDecisions[i])
		}
		if !strings.HasPrefix(event.ActionDigest, policy.ToolActionDigestAlgorithm+":sha256:") {
			t.Fatalf("event %d missing exact action binding: %q", i+1, event.ActionDigest)
		}
		if !strings.HasPrefix(event.PolicyDigest, policy.ResolvedPolicyDigestAlgorithm+":sha256:") {
			t.Fatalf("event %d missing effective policy binding: %q", i+1, event.PolicyDigest)
		}
	}

	f, err := os.Open(auditFile)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if n, err := audit.VerifyChain(f); err != nil || n != len(events) {
		t.Fatalf("VerifyChain = (%d, %v), want (%d, nil)", n, err, len(events))
	}
}

func TestRunCheckActionDigestChangesWithArguments(t *testing.T) {
	dir := t.TempDir()
	policyFile := filepath.Join(dir, "policy.yaml")
	callFile := filepath.Join(dir, "calls.jsonl")
	auditFile := filepath.Join(dir, "audit.jsonl")

	writeTestFile(t, policyFile, []byte(`version: "0.1"
defaults:
  decision: deny
tools:
  demo.tool:
    decision: allow
`))
	writeTestFile(t, callFile, []byte("{\"id\":\"a\",\"tool\":\"demo.tool\",\"arguments\":{\"value\":\"alpha\"}}\n"+
		"{\"id\":\"b\",\"tool\":\"demo.tool\",\"arguments\":{\"value\":\"beta\"}}\n"))

	if _, _, err := captureOutput(t, func() error {
		return runCheck([]string{"--policy", policyFile, "--call", callFile, "--audit-log", auditFile, "--output", "json"})
	}); err != nil {
		t.Fatalf("runCheck: %v", err)
	}

	events := readBoundCheckEvents(t, auditFile)
	if len(events) != 2 {
		t.Fatalf("events = %d, want 2", len(events))
	}
	if events[0].ActionDigest == events[1].ActionDigest {
		t.Fatalf("changed arguments reused action digest %q", events[0].ActionDigest)
	}
	if events[0].PolicyDigest != events[1].PolicyDigest {
		t.Fatalf("unchanged policy changed digest: %q != %q", events[0].PolicyDigest, events[1].PolicyDigest)
	}
}

func TestRunCheckPolicyDigestTracksEffectiveImportedPolicy(t *testing.T) {
	dir := t.TempDir()
	rootFile := filepath.Join(dir, "root.yaml")
	childFile := filepath.Join(dir, "child.yaml")
	callFile := filepath.Join(dir, "calls.jsonl")

	writeTestFile(t, rootFile, []byte(`version: "0.1"
imports:
  - child.yaml
defaults:
  decision: deny
`))
	writeTestFile(t, childFile, []byte(`version: "0.1"
tools:
  demo.tool:
    decision: allow
`))
	writeTestFile(t, callFile, []byte("{\"id\":\"same\",\"tool\":\"demo.tool\",\"arguments\":{\"value\":\"same\"}}\n"))

	firstAudit := filepath.Join(dir, "first.jsonl")
	if _, _, err := captureOutput(t, func() error {
		return runCheck([]string{"--policy", rootFile, "--call", callFile, "--audit-log", firstAudit, "--output", "json"})
	}); err != nil {
		t.Fatalf("first runCheck: %v", err)
	}
	first := readBoundCheckEvents(t, firstAudit)
	if len(first) != 1 || first[0].Decision != policy.DecisionAllow {
		t.Fatalf("first event = %+v, want one allow", first)
	}

	writeTestFile(t, childFile, []byte(`version: "0.1"
tools:
  demo.tool:
    decision: deny
`))
	secondAudit := filepath.Join(dir, "second.jsonl")
	if _, _, err := captureOutput(t, func() error {
		return runCheck([]string{"--policy", rootFile, "--call", callFile, "--audit-log", secondAudit, "--output", "json"})
	}); err != nil {
		t.Fatalf("second runCheck: %v", err)
	}
	second := readBoundCheckEvents(t, secondAudit)
	if len(second) != 1 || second[0].Decision != policy.DecisionDeny {
		t.Fatalf("second event = %+v, want one deny", second)
	}
	if first[0].ActionDigest != second[0].ActionDigest {
		t.Fatalf("same action changed digest: %q != %q", first[0].ActionDigest, second[0].ActionDigest)
	}
	if first[0].PolicyDigest == second[0].PolicyDigest {
		t.Fatalf("changed effective imported policy reused digest %q", first[0].PolicyDigest)
	}
}

func TestRunCheckAmbiguousJSONFailsClosedBeforeBinding(t *testing.T) {
	dir := t.TempDir()
	policyFile := filepath.Join(dir, "policy.yaml")
	callFile := filepath.Join(dir, "calls.jsonl")
	auditFile := filepath.Join(dir, "audit.jsonl")

	writeTestFile(t, policyFile, []byte(`version: "0.1"
defaults:
  decision: deny
tools:
  demo.tool:
    decision: allow
`))
	writeTestFile(t, callFile, []byte("{\"id\":\"dup\",\"tool\":\"demo.tool\",\"arguments\":{\"value\":1,\"value\":2}}\n"))

	_, _, err := captureOutput(t, func() error {
		return runCheck([]string{
			"--policy", policyFile,
			"--call", callFile,
			"--audit-log", auditFile,
			"--output", "json",
			"--tamper-evident",
		})
	})
	if err == nil || !strings.Contains(err.Error(), "failed to parse") {
		t.Fatalf("runCheck error = %v, want explicit parse failure", err)
	}

	events := readBoundCheckEvents(t, auditFile)
	if len(events) != 1 {
		t.Fatalf("events = %d, want 1 fail-closed event", len(events))
	}
	event := events[0]
	if event.Decision != policy.DecisionDeny || event.ReasonCode != policy.ReasonCodeParseError {
		t.Fatalf("event = %+v, want explicit parse-error deny", event)
	}
	if event.ActionDigest != "" || event.PolicyDigest != "" {
		t.Fatalf("ambiguous input unexpectedly acquired binding evidence: action=%q policy=%q", event.ActionDigest, event.PolicyDigest)
	}
}

func readBoundCheckEvents(t *testing.T, path string) []audit.Event {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	var events []audit.Event
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)
	for scanner.Scan() {
		var event audit.Event
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			t.Fatalf("decode audit event: %v", err)
		}
		events = append(events, event)
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	return events
}
