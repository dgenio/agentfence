package main

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

// observabilityFixture writes a policy that denies a .env read and allows other
// reads, plus a two-line call trace (one allow, one deny), and returns the file
// paths.
func observabilityFixture(t *testing.T) (policyFile, callFile string) {
	t.Helper()
	dir := t.TempDir()
	policyFile = filepath.Join(dir, "policy.yaml")
	callFile = filepath.Join(dir, "calls.jsonl")
	writeTestFile(t, policyFile, []byte(`version: "0.1"
defaults:
  decision: deny
tools:
  filesystem.read:
    decision: allow
    constraints:
      paths:
        deny: ["**/.env"]
`))
	writeTestFile(t, callFile, []byte(`{"id":"c1","tool":"filesystem.read","arguments":{"path":"README.md"}}
{"id":"c2","tool":"filesystem.read","arguments":{"path":".env"}}
`))
	return policyFile, callFile
}

// TestCheckMetricsSummary verifies --metrics prints a decision summary to stderr
// without polluting stdout (#169).
func TestCheckMetricsSummary(t *testing.T) {
	policyFile, callFile := observabilityFixture(t)

	stdout, stderr, err := captureOutput(t, func() error {
		return runCheck([]string{"--policy", policyFile, "--call", callFile, "--output", "json", "--metrics"})
	})
	if err != nil {
		t.Fatalf("runCheck error = %v", err)
	}

	// The metrics summary goes to stderr, never stdout (stdout is the JSON
	// decision stream and must stay parseable).
	if !strings.Contains(stderr, "Decision metrics") {
		t.Errorf("stderr missing metrics summary:\n%s", stderr)
	}
	if !strings.Contains(stderr, "allow=1 deny=1") {
		t.Errorf("stderr metrics counts wrong:\n%s", stderr)
	}
	if !strings.Contains(stderr, "path_denied") {
		t.Errorf("stderr metrics missing reason code:\n%s", stderr)
	}
	// stdout must remain valid JSON (the decision array).
	var summaries []map[string]interface{}
	if err := json.Unmarshal([]byte(stdout), &summaries); err != nil {
		t.Fatalf("stdout is not valid JSON with --metrics: %v\n%s", err, stdout)
	}
}

// TestCheckLogFormatJSONParseError verifies --log-format json emits a structured
// operational record for a parse error to stderr (#163), while stdout carries the
// decision stream.
func TestCheckLogFormatJSONParseError(t *testing.T) {
	dir := t.TempDir()
	policyFile := filepath.Join(dir, "policy.yaml")
	callFile := filepath.Join(dir, "calls.jsonl")
	writeTestFile(t, policyFile, []byte(`version: "0.1"
defaults:
  decision: deny
tools:
  filesystem.read:
    decision: allow
`))
	// One good line, one malformed line.
	writeTestFile(t, callFile, []byte(`{"id":"c1","tool":"filesystem.read","arguments":{"path":"README.md"}}
not json
`))

	_, stderr, err := captureOutput(t, func() error {
		return runCheck([]string{"--policy", policyFile, "--call", callFile, "--output", "json", "--log-format", "json"})
	})
	if err != nil {
		t.Fatalf("runCheck error = %v", err)
	}

	// stderr should contain a JSON operational record for the parse failure.
	var found bool
	for _, line := range strings.Split(strings.TrimSpace(stderr), "\n") {
		if line == "" {
			continue
		}
		var rec map[string]interface{}
		if json.Unmarshal([]byte(line), &rec) != nil {
			continue
		}
		if msg, _ := rec["msg"].(string); strings.Contains(msg, "failed to parse") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a structured parse-error record on stderr:\n%s", stderr)
	}
}

// TestCheckLogFormatInvalid rejects an unknown --log-format value.
func TestCheckLogFormatInvalid(t *testing.T) {
	policyFile, callFile := observabilityFixture(t)
	err := runCheck([]string{"--policy", policyFile, "--call", callFile, "--log-format", "xml"})
	if err == nil {
		t.Fatal("expected error for invalid --log-format")
	}
	if !strings.Contains(err.Error(), "log format") {
		t.Fatalf("error %q should mention the log format", err)
	}
}

// TestCheckTextOutputUnchangedByDefault is a guard that the default (text) path
// does not emit the metrics summary or structured logs, preserving the existing
// stderr contract (#163 "text default unchanged").
func TestCheckTextOutputUnchangedByDefault(t *testing.T) {
	policyFile, callFile := observabilityFixture(t)
	_, stderr, err := captureOutput(t, func() error {
		return runCheck([]string{"--policy", policyFile, "--call", callFile})
	})
	if err != nil {
		t.Fatalf("runCheck error = %v", err)
	}
	if strings.Contains(stderr, "Decision metrics") {
		t.Errorf("default run must not print metrics summary:\n%s", stderr)
	}
}
