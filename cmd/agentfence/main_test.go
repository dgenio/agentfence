package main

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/dgenio/agentfence/internal/audit"
)

// writeTestFile writes data to path and fails the test if the write errors.
func writeTestFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
}

func captureOutput(t *testing.T, fn func() error) (string, string, error) {
	t.Helper()
	stdoutR, stdoutW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	stderrR, stderrW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	oldStdout := os.Stdout
	oldStderr := os.Stderr
	os.Stdout = stdoutW
	os.Stderr = stderrW

	runErr := fn()

	stdoutW.Close()
	stderrW.Close()
	os.Stdout = oldStdout
	os.Stderr = oldStderr

	var stdout, stderr bytes.Buffer
	if _, err := io.Copy(&stdout, stdoutR); err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(&stderr, stderrR); err != nil {
		t.Fatal(err)
	}
	return stdout.String(), stderr.String(), runErr
}

func TestRunCheckRequiresFlags(t *testing.T) {
	err := runCheck([]string{})
	if err == nil {
		t.Fatal("expected error when --policy and --call are missing")
	}
}

func TestRunCheckWithValidInput(t *testing.T) {
	dir := t.TempDir()
	policyFile := filepath.Join(dir, "policy.yaml")
	callFile := filepath.Join(dir, "calls.jsonl")

	policyContent := `version: "0.1"
defaults:
  decision: deny
tools:
  filesystem.read:
    decision: allow
`
	if err := os.WriteFile(policyFile, []byte(policyContent), 0o644); err != nil {
		t.Fatal(err)
	}

	callContent := `{"id":"call_1","tool":"filesystem.read","arguments":{"path":"README.md"}}
`
	if err := os.WriteFile(callFile, []byte(callContent), 0o644); err != nil {
		t.Fatal(err)
	}

	err := runCheck([]string{"--policy", policyFile, "--call", callFile})
	if err != nil {
		t.Fatalf("runCheck() error = %v", err)
	}
}

func TestRunCheckRejectsTypoPolicy(t *testing.T) {
	dir := t.TempDir()
	policyFile := filepath.Join(dir, "policy.yaml")
	callFile := filepath.Join(dir, "calls.jsonl")

	writeTestFile(t, policyFile, []byte(`version: "0.1"
defaults:
  decision: deny
tools:
  filesystem.read:
    decision: allow
    constraints:
      paths:
        allowwww: ["./"]
`))
	writeTestFile(t, callFile, []byte(`{"id":"call_1","tool":"filesystem.read","arguments":{"path":"README.md"}}
`))

	err := runCheck([]string{"--policy", policyFile, "--call", callFile})
	if err == nil {
		t.Fatal("expected typo policy to be rejected")
	}
	if !strings.Contains(err.Error(), "allowwww") {
		t.Fatalf("error %q does not mention typo field", err)
	}
}

func TestHelpFlagsExitZero(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{name: "no args", args: []string{}},
		{name: "top help long", args: []string{"--help"}},
		{name: "top help short", args: []string{"-h"}},
		{name: "help command", args: []string{"help"}},
		{name: "help check", args: []string{"help", "check"}},
		{name: "check help", args: []string{"check", "--help"}},
		{name: "proxy help", args: []string{"proxy", "--help"}},
		{name: "validate help", args: []string{"validate", "-h"}},
		{name: "policy help", args: []string{"policy", "--help"}},
		{name: "audit help", args: []string{"audit", "--help"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := captureOutput(t, func() error {
				return runRoot(tt.args)
			})
			if err != nil {
				t.Fatalf("runRoot(%v) error = %v", tt.args, err)
			}
		})
	}
}

func TestRunRootUnknownCommandStillErrors(t *testing.T) {
	_, _, err := captureOutput(t, func() error {
		return runRoot([]string{"bogus"})
	})
	if err == nil {
		t.Fatal("expected unknown command to error")
	}
	if !strings.Contains(err.Error(), "unknown command") {
		t.Fatalf("error = %v, want unknown command", err)
	}
}

func TestRunInitCreatesFile(t *testing.T) {
	dir := t.TempDir()
	orig, _ := os.Getwd()
	defer os.Chdir(orig)
	os.Chdir(dir)

	err := runInit()
	if err != nil {
		t.Fatalf("runInit() error = %v", err)
	}

	if _, err := os.Stat(filepath.Join(dir, "agentfence.yaml")); os.IsNotExist(err) {
		t.Fatal("expected agentfence.yaml to be created")
	}
}

func TestRunInitFailsIfFileExists(t *testing.T) {
	dir := t.TempDir()
	orig, _ := os.Getwd()
	defer os.Chdir(orig)
	os.Chdir(dir)

	writeTestFile(t, "agentfence.yaml", []byte("existing"))

	err := runInit()
	if err == nil {
		t.Fatal("expected error when file already exists")
	}
}

// TestVersionCommand verifies that runVersion writes a non-empty version string
// containing the binary name.
func TestVersionCommand(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	oldStdout := os.Stdout
	os.Stdout = w

	runVersion()

	w.Close()
	os.Stdout = oldStdout

	var buf bytes.Buffer
	if _, err := io.Copy(&buf, r); err != nil {
		t.Fatal(err)
	}

	output := buf.String()
	if !strings.Contains(output, "agentfence") {
		t.Fatalf("version output %q does not contain 'agentfence'", output)
	}
	if !strings.Contains(output, Version) {
		t.Fatalf("version output %q does not contain version %q", output, Version)
	}
}

// TestValidateCommandOK verifies that a valid policy exits cleanly.
func TestValidateCommandOK(t *testing.T) {
	dir := t.TempDir()
	policyFile := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(policyFile, []byte(`version: "0.1"
defaults:
  decision: deny
`), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := runValidate([]string{"--policy", policyFile}); err != nil {
		t.Fatalf("runValidate() unexpected error: %v", err)
	}
}

// TestValidateCommandDetectsTypo verifies that an unknown field returns an error.
func TestValidateCommandDetectsTypo(t *testing.T) {
	dir := t.TempDir()
	policyFile := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(policyFile, []byte(`version: "0.1"
defaults:
  decisoin: deny
`), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := runValidate([]string{"--policy", policyFile}); err == nil {
		t.Fatal("runValidate() expected error for unknown field 'decisoin', got nil")
	}
}

// TestValidateCommandDetectsBadDecision verifies that an invalid decision value
// returns an error.
func TestValidateCommandDetectsBadDecision(t *testing.T) {
	dir := t.TempDir()
	policyFile := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(policyFile, []byte(`version: "0.1"
defaults:
  decision: maybe
`), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := runValidate([]string{"--policy", policyFile}); err == nil {
		t.Fatal("runValidate() expected error for invalid decision 'maybe', got nil")
	}
}

func TestValidateOutputIncludesGotValue(t *testing.T) {
	dir := t.TempDir()
	policyFile := filepath.Join(dir, "policy.yaml")
	writeTestFile(t, policyFile, []byte(`version: "0.1"
defaults:
  decision: maybe
`))

	_, stderr, err := captureOutput(t, func() error {
		return runValidate([]string{"--policy", policyFile})
	})
	if err == nil {
		t.Fatal("expected validation error")
	}
	if !strings.Contains(stderr, `(got "maybe")`) {
		t.Fatalf("stderr %q does not include got-value suffix", stderr)
	}
}

// TestValidateCommandRequiresPolicy verifies --policy is mandatory.
func TestValidateCommandRequiresPolicy(t *testing.T) {
	if err := runValidate([]string{}); err == nil {
		t.Fatal("runValidate() expected error when --policy is missing")
	}
}

// TestCheckOutputModes verifies that --output json and --output jsonl produce
// parseable structured output.
func TestCheckOutputModes(t *testing.T) {
	dir := t.TempDir()
	policyFile := filepath.Join(dir, "policy.yaml")
	callFile := filepath.Join(dir, "calls.jsonl")

	if err := os.WriteFile(policyFile, []byte(`version: "0.1"
defaults:
  decision: deny
tools:
  filesystem.read:
    decision: allow
`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(callFile, []byte(`{"id":"call_1","tool":"filesystem.read","arguments":{"path":"README.md"}}
`), 0o644); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		mode string
	}{
		{"json"},
		{"jsonl"},
	}
	for _, tt := range tests {
		t.Run(tt.mode, func(t *testing.T) {
			r, w, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			oldStdout := os.Stdout
			os.Stdout = w

			runErr := runCheck([]string{"--policy", policyFile, "--call", callFile, "--output", tt.mode})

			w.Close()
			os.Stdout = oldStdout

			var buf bytes.Buffer
			if _, err := io.Copy(&buf, r); err != nil {
				t.Fatal(err)
			}

			if runErr != nil {
				t.Fatalf("runCheck --output %s error = %v", tt.mode, runErr)
			}

			output := strings.TrimSpace(buf.String())

			switch tt.mode {
			case "json":
				var summaries []DecisionSummary
				if err := json.Unmarshal([]byte(output), &summaries); err != nil {
					t.Fatalf("--output json: invalid JSON: %v\noutput: %s", err, output)
				}
				if len(summaries) == 0 {
					t.Fatal("--output json: expected at least one decision in array")
				}
			case "jsonl":
				lines := strings.Split(output, "\n")
				// Skip trailing summary line which starts with a digit (text summary)
				for i, line := range lines {
					if line == "" {
						continue
					}
					var s DecisionSummary
					if err := json.Unmarshal([]byte(line), &s); err != nil {
						t.Fatalf("--output jsonl line %d: invalid JSON: %v\nline: %q", i+1, err, line)
					}
				}
			}
		})
	}
}

// TestCheckOutputUnknownMode verifies that an unrecognised --output value
// returns an error.
func TestCheckOutputUnknownMode(t *testing.T) {
	dir := t.TempDir()
	policyFile := filepath.Join(dir, "policy.yaml")
	callFile := filepath.Join(dir, "calls.jsonl")
	writeTestFile(t, policyFile, []byte(`version: "0.1"
defaults:
  decision: deny
`))
	writeTestFile(t, callFile, []byte(""))

	err := runCheck([]string{"--policy", policyFile, "--call", callFile, "--output", "xml"})
	if err == nil {
		t.Fatal("expected error for unknown --output mode 'xml'")
	}
}

func TestCheckAuditLogAppends(t *testing.T) {
	dir := t.TempDir()
	policyFile := filepath.Join(dir, "policy.yaml")
	callFile := filepath.Join(dir, "calls.jsonl")
	auditFile := filepath.Join(dir, "audit.jsonl")

	writeTestFile(t, policyFile, []byte(`version: "0.1"
defaults:
  decision: deny
tools:
  filesystem.read:
    decision: allow
`))
	writeTestFile(t, callFile, []byte(`{"id":"c1","tool":"filesystem.read","arguments":{"path":"README.md"}}
`))

	for i := 0; i < 2; i++ {
		if err := runCheck([]string{
			"--policy", policyFile,
			"--call", callFile,
			"--audit-log", auditFile,
			"--output", "json",
		}); err != nil {
			t.Fatalf("runCheck pass %d: %v", i+1, err)
		}
	}

	b, err := os.ReadFile(auditFile)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	if len(lines) != 2 {
		t.Fatalf("audit log line count = %d, want 2\n%s", len(lines), string(b))
	}
}

func TestCheckAuditLogPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX file mode assertion does not apply on Windows")
	}
	dir := t.TempDir()
	policyFile := filepath.Join(dir, "policy.yaml")
	callFile := filepath.Join(dir, "calls.jsonl")
	auditFile := filepath.Join(dir, "audit.jsonl")

	writeTestFile(t, policyFile, []byte(`version: "0.1"
defaults:
  decision: deny
tools:
  filesystem.read:
    decision: allow
`))
	writeTestFile(t, callFile, []byte(`{"id":"c1","tool":"filesystem.read","arguments":{"path":"README.md"}}
`))

	if err := runCheck([]string{
		"--policy", policyFile,
		"--call", callFile,
		"--audit-log", auditFile,
		"--output", "json",
	}); err != nil {
		t.Fatalf("runCheck: %v", err)
	}
	info, err := os.Stat(auditFile)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("audit file mode = %o, want 600", got)
	}
}

func TestCheckAuditLogTamperEvidentChainSurvivesReruns(t *testing.T) {
	dir := t.TempDir()
	policyFile := filepath.Join(dir, "policy.yaml")
	callFile := filepath.Join(dir, "calls.jsonl")
	auditFile := filepath.Join(dir, "audit.jsonl")

	writeTestFile(t, policyFile, []byte(`version: "0.1"
defaults:
  decision: deny
tools:
  filesystem.read:
    decision: allow
`))
	writeTestFile(t, callFile, []byte(`{"id":"c1","tool":"filesystem.read","arguments":{"path":"README.md"}}
`))

	for i := 0; i < 2; i++ {
		if err := runCheck([]string{
			"--policy", policyFile,
			"--call", callFile,
			"--audit-log", auditFile,
			"--output", "json",
			"--tamper-evident",
		}); err != nil {
			t.Fatalf("runCheck pass %d: %v", i+1, err)
		}
	}

	f, err := os.Open(auditFile)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	n, err := audit.VerifyChain(f)
	if err != nil {
		t.Fatalf("VerifyChain() error = %v", err)
	}
	if n != 2 {
		t.Fatalf("verified event count = %d, want 2", n)
	}
}

// TestCheckHandlesMalformedLine verifies that a single bad JSONL line does not
// abort evaluation of subsequent calls and that the command returns nil.
func TestCheckHandlesMalformedLine(t *testing.T) {
	dir := t.TempDir()
	policyFile := filepath.Join(dir, "policy.yaml")
	callFile := filepath.Join(dir, "calls.jsonl")

	if err := os.WriteFile(policyFile, []byte(`version: "0.1"
defaults:
  decision: deny
tools:
  filesystem.read:
    decision: allow
`), 0o644); err != nil {
		t.Fatal(err)
	}

	// Line 1: valid; line 2: malformed JSON; line 3: valid.
	callContent := `{"id":"call_1","tool":"filesystem.read","arguments":{"path":"README.md"}}
this is not json
{"id":"call_3","tool":"filesystem.read","arguments":{"path":"go.mod"}}
`
	if err := os.WriteFile(callFile, []byte(callContent), 0o644); err != nil {
		t.Fatal(err)
	}

	// Capture stdout to count output lines.
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	oldStdout := os.Stdout
	os.Stdout = w

	runErr := runCheck([]string{"--policy", policyFile, "--call", callFile})

	w.Close()
	os.Stdout = oldStdout

	var buf bytes.Buffer
	io.Copy(&buf, r)

	if runErr != nil {
		t.Fatalf("runCheck() returned unexpected error for malformed line: %v", runErr)
	}

	output := buf.String()
	// All three lines should produce output (valid call_1, error line-2, valid call_3).
	if !strings.Contains(output, "call_1") {
		t.Error("expected call_1 to appear in output")
	}
	if !strings.Contains(output, "line-2") {
		t.Error("expected line-2 error entry to appear in output")
	}
	if !strings.Contains(output, "call_3") {
		t.Error("expected call_3 to appear in output")
	}
}

func TestCheckParseErrorOrderMatchesNormalCall(t *testing.T) {
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
	writeTestFile(t, callFile, []byte(`{"id":"c1","tool":"filesystem.read","arguments":{"path":"README.md"}}
not json
`))

	stdout, _, err := captureOutput(t, func() error {
		return runCheck([]string{"--policy", policyFile, "--call", callFile})
	})
	if err != nil {
		t.Fatalf("runCheck() error = %v", err)
	}

	var lines []string
	for _, line := range strings.Split(stdout, "\n") {
		if strings.TrimSpace(line) != "" {
			lines = append(lines, line)
		}
	}
	if len(lines) < 5 {
		t.Fatalf("expected at least 5 output lines, got %d:\n%s", len(lines), stdout)
	}
	if !strings.HasPrefix(lines[0], "c1 filesystem.read -> allow") {
		t.Fatalf("normal call text line = %q", lines[0])
	}
	if !strings.HasPrefix(lines[1], "{") {
		t.Fatalf("normal call audit line = %q", lines[1])
	}
	if !strings.HasPrefix(lines[2], "line-2  -> deny") {
		t.Fatalf("parse error text line = %q", lines[2])
	}
	if !strings.HasPrefix(lines[3], "{") {
		t.Fatalf("parse error audit line = %q", lines[3])
	}
}

// TestCheckAllMalformedReturnsError verifies that an all-malformed input is
// treated as an error (no calls were evaluated).
func TestCheckAllMalformedReturnsError(t *testing.T) {
	dir := t.TempDir()
	policyFile := filepath.Join(dir, "policy.yaml")
	callFile := filepath.Join(dir, "calls.jsonl")

	writeTestFile(t, policyFile, []byte(`version: "0.1"
defaults:
  decision: deny
`))
	writeTestFile(t, callFile, []byte("not json\nalso not json\n"))

	err := runCheck([]string{"--policy", policyFile, "--call", callFile})
	if err == nil {
		t.Fatal("expected error when all lines fail to parse")
	}
}

// ── #18: --fail-on ────────────────────────────────────────────────────────────

func TestCheckFailOnDeny(t *testing.T) {
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
	writeTestFile(t, callFile, []byte(`{"id":"c1","tool":"filesystem.read","arguments":{"path":"README.md"}}
{"id":"c2","tool":"unknown.tool","arguments":{}}
`))

	// Without --fail-on: should succeed even though one call is denied.
	if err := runCheck([]string{"--policy", policyFile, "--call", callFile}); err != nil {
		t.Fatalf("runCheck without --fail-on should not error: %v", err)
	}

	// With --fail-on deny: should fail because c2 is denied.
	err := runCheck([]string{"--policy", policyFile, "--call", callFile, "--fail-on", "deny"})
	if err == nil {
		t.Fatal("expected error with --fail-on deny when a call is denied")
	}
}

func TestCheckFailOnAsk(t *testing.T) {
	dir := t.TempDir()
	policyFile := filepath.Join(dir, "policy.yaml")
	callFile := filepath.Join(dir, "calls.jsonl")

	writeTestFile(t, policyFile, []byte(`version: "0.1"
defaults:
  decision: deny
tools:
  github.create_issue:
    decision: ask
`))
	writeTestFile(t, callFile, []byte(`{"id":"c1","tool":"github.create_issue","arguments":{}}
`))

	// --dry-run preserves the ask decision (the approver is bypassed) so that
	// --fail-on ask sees what would have been asked. This is the canonical CI
	// pattern: "evaluate without enforcing, but flag if any ask would happen."
	// In dry-run, --fail-on reports but does not propagate non-zero exit.
	if err := runCheck([]string{"--policy", policyFile, "--call", callFile, "--fail-on", "ask", "--dry-run"}); err != nil {
		t.Fatalf("runCheck --dry-run --fail-on ask should report without erroring, got: %v", err)
	}

	// Without --dry-run, the default TTY approver in a test environment denies
	// (no TTY, no stdin input), so the ask is converted to deny and --fail-on
	// ask no longer matches. Explicitly use --no-interactive to make this
	// behavior deterministic across environments.
	err := runCheck([]string{"--policy", policyFile, "--call", callFile, "--fail-on", "ask", "--no-interactive"})
	if err != nil {
		t.Fatalf("with --no-interactive, ask is converted to deny so --fail-on ask should not match: %v", err)
	}
}

func TestCheckFailOnAllCallsEvaluated(t *testing.T) {
	dir := t.TempDir()
	policyFile := filepath.Join(dir, "policy.yaml")
	callFile := filepath.Join(dir, "calls.jsonl")

	writeTestFile(t, policyFile, []byte(`version: "0.1"
defaults:
  decision: deny
tools:
  tool.a:
    decision: allow
  tool.b:
    decision: deny
  tool.c:
    decision: allow
`))
	// Three calls: a (allow), b (deny triggers --fail-on), c (allow).
	// All three should be evaluated; error returned at end.
	writeTestFile(t, callFile, []byte(`{"id":"c1","tool":"tool.a","arguments":{}}
{"id":"c2","tool":"tool.b","arguments":{}}
{"id":"c3","tool":"tool.c","arguments":{}}
`))

	r, w, _ := os.Pipe()
	oldStdout := os.Stdout
	os.Stdout = w

	err := runCheck([]string{"--policy", policyFile, "--call", callFile, "--fail-on", "deny"})

	w.Close()
	os.Stdout = oldStdout
	var buf bytes.Buffer
	io.Copy(&buf, r)

	if err == nil {
		t.Fatal("expected error with --fail-on deny")
	}
	// All three calls should appear in output.
	output := buf.String()
	for _, id := range []string{"c1", "c2", "c3"} {
		if !strings.Contains(output, id) {
			t.Errorf("expected %s to appear in output; got: %s", id, output)
		}
	}
}

func TestCheckFailOnRejectsAllow(t *testing.T) {
	dir := t.TempDir()
	policyFile := filepath.Join(dir, "policy.yaml")
	callFile := filepath.Join(dir, "calls.jsonl")
	writeTestFile(t, policyFile, []byte(`version: "0.1"
defaults:
  decision: deny
`))
	writeTestFile(t, callFile, []byte(""))

	err := runCheck([]string{"--policy", policyFile, "--call", callFile, "--fail-on", "allow"})
	if err == nil {
		t.Fatal("expected error for --fail-on allow")
	}
}

// ── #19: explain command ──────────────────────────────────────────────────────

func TestExplainCommandRejectsNullArgs(t *testing.T) {
	dir := t.TempDir()
	policyFile := filepath.Join(dir, "policy.yaml")
	writeTestFile(t, policyFile, []byte(`version: "0.1"
defaults:
  decision: deny
`))

	err := runExplain([]string{"--policy", policyFile, "--tool", "foo", "--args", "null"})
	if err == nil {
		t.Fatal("expected error for --args null")
	}
}

func TestExplainCommandExplicitRule(t *testing.T) {
	dir := t.TempDir()
	policyFile := filepath.Join(dir, "policy.yaml")
	writeTestFile(t, policyFile, []byte(`version: "0.1"
defaults:
  decision: deny
tools:
  filesystem.write:
    decision: ask
    constraints:
      paths:
        allow: ["./src/**"]
        deny: [".env"]
`))

	r, w, _ := os.Pipe()
	oldStdout := os.Stdout
	os.Stdout = w

	err := runExplain([]string{"--policy", policyFile, "--tool", "filesystem.write", "--args", `{"path":".env"}`})

	w.Close()
	os.Stdout = oldStdout
	var buf bytes.Buffer
	io.Copy(&buf, r)

	if err != nil {
		t.Fatalf("runExplain unexpected error: %v", err)
	}
	output := buf.String()
	if !strings.Contains(output, "deny") {
		t.Errorf("expected 'deny' in output; got: %s", output)
	}
	if !strings.Contains(output, "trace") {
		t.Errorf("expected 'trace' in output; got: %s", output)
	}
}

func TestExplainCommandDefaultDecision(t *testing.T) {
	dir := t.TempDir()
	policyFile := filepath.Join(dir, "policy.yaml")
	writeTestFile(t, policyFile, []byte(`version: "0.1"
defaults:
  decision: deny
`))

	r, w, _ := os.Pipe()
	oldStdout := os.Stdout
	os.Stdout = w

	err := runExplain([]string{"--policy", policyFile, "--tool", "unknown.tool"})

	w.Close()
	os.Stdout = oldStdout
	var buf bytes.Buffer
	io.Copy(&buf, r)

	if err != nil {
		t.Fatalf("runExplain unexpected error: %v", err)
	}
	output := buf.String()
	if !strings.Contains(output, "deny") {
		t.Errorf("expected 'deny' in output; got: %s", output)
	}
}

func TestExplainCommandJSONOutput(t *testing.T) {
	dir := t.TempDir()
	policyFile := filepath.Join(dir, "policy.yaml")
	writeTestFile(t, policyFile, []byte(`version: "0.1"
defaults:
  decision: deny
tools:
  github.delete_repo:
    decision: deny
`))

	r, w, _ := os.Pipe()
	oldStdout := os.Stdout
	os.Stdout = w

	err := runExplain([]string{"--policy", policyFile, "--tool", "github.delete_repo", "--output", "json"})

	w.Close()
	os.Stdout = oldStdout
	var buf bytes.Buffer
	io.Copy(&buf, r)

	if err != nil {
		t.Fatalf("runExplain unexpected error: %v", err)
	}

	var out struct {
		Tool     string   `json:"tool"`
		Decision string   `json:"decision"`
		Reason   string   `json:"reason"`
		Trace    []string `json:"trace"`
	}
	if err := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &out); err != nil {
		t.Fatalf("JSON output parse error: %v\noutput: %s", err, buf.String())
	}
	if out.Decision != "deny" {
		t.Errorf("expected decision 'deny', got %q", out.Decision)
	}
	if out.Tool != "github.delete_repo" {
		t.Errorf("expected tool 'github.delete_repo', got %q", out.Tool)
	}
	if len(out.Trace) == 0 {
		t.Error("expected non-empty trace in JSON output")
	}
}

func TestExplainCommandMissingTool(t *testing.T) {
	dir := t.TempDir()
	policyFile := filepath.Join(dir, "policy.yaml")
	writeTestFile(t, policyFile, []byte(`version: "0.1"
defaults:
  decision: deny
`))

	err := runExplain([]string{"--policy", policyFile})
	if err == nil {
		t.Fatal("expected error when --tool is missing")
	}
}

func TestExplainCommandUnknownOutput(t *testing.T) {
	dir := t.TempDir()
	policyFile := filepath.Join(dir, "policy.yaml")
	writeTestFile(t, policyFile, []byte(`version: "0.1"
defaults:
  decision: deny
`))

	err := runExplain([]string{"--policy", policyFile, "--tool", "foo", "--output", "xml"})
	if err == nil {
		t.Fatal("expected error for unknown --output mode")
	}
}

// ── #20: policy test command ──────────────────────────────────────────────────

func TestPolicyTestCommandAllPass(t *testing.T) {
	dir := t.TempDir()
	policyFile := filepath.Join(dir, "policy.yaml")
	testsFile := filepath.Join(dir, "tests.yaml")

	writeTestFile(t, policyFile, []byte(`version: "0.1"
defaults:
  decision: deny
tools:
  filesystem.read:
    decision: allow
    constraints:
      paths:
        allow: ["./"]
        deny: [".env"]
`))
	writeTestFile(t, testsFile, []byte(`tests:
  - id: allow-readme
    tool: filesystem.read
    arguments:
      path: README.md
    expect: allow
  - id: deny-env
    tool: filesystem.read
    arguments:
      path: .env
    expect: deny
  - id: deny-unknown
    tool: unknown.tool
    arguments: {}
    expect: deny
`))

	r, w, _ := os.Pipe()
	oldStdout := os.Stdout
	os.Stdout = w

	err := runPolicyTest([]string{"--policy", policyFile, "--tests", testsFile})

	w.Close()
	os.Stdout = oldStdout
	var buf bytes.Buffer
	io.Copy(&buf, r)

	if err != nil {
		t.Fatalf("runPolicyTest error: %v\noutput: %s", err, buf.String())
	}
	output := buf.String()
	if !strings.Contains(output, "PASS: allow-readme") {
		t.Errorf("expected PASS for allow-readme; got: %s", output)
	}
}

func TestPolicyTestCommandFailure(t *testing.T) {
	dir := t.TempDir()
	policyFile := filepath.Join(dir, "policy.yaml")
	testsFile := filepath.Join(dir, "tests.yaml")

	writeTestFile(t, policyFile, []byte(`version: "0.1"
defaults:
  decision: deny
`))
	writeTestFile(t, testsFile, []byte(`tests:
  - id: wrong-expectation
    tool: some.tool
    arguments: {}
    expect: allow
`))

	r, w, _ := os.Pipe()
	oldStdout := os.Stdout
	os.Stdout = w

	err := runPolicyTest([]string{"--policy", policyFile, "--tests", testsFile})

	w.Close()
	os.Stdout = oldStdout
	var buf bytes.Buffer
	io.Copy(&buf, r)

	if err == nil {
		t.Fatal("expected error when a test fails")
	}
	output := buf.String()
	if !strings.Contains(output, "FAIL") {
		t.Errorf("expected FAIL line in output; got: %s", output)
	}
}

func TestPolicyTestCommandVerbose(t *testing.T) {
	dir := t.TempDir()
	policyFile := filepath.Join(dir, "policy.yaml")
	testsFile := filepath.Join(dir, "tests.yaml")

	writeTestFile(t, policyFile, []byte(`version: "0.1"
defaults:
  decision: deny
tools:
  filesystem.read:
    decision: allow
`))
	writeTestFile(t, testsFile, []byte(`tests:
  - id: allow-read
    tool: filesystem.read
    arguments: {}
    expect: allow
`))

	r, w, _ := os.Pipe()
	oldStdout := os.Stdout
	os.Stdout = w

	err := runPolicyTest([]string{"--policy", policyFile, "--tests", testsFile, "--verbose"})

	w.Close()
	os.Stdout = oldStdout
	var buf bytes.Buffer
	io.Copy(&buf, r)

	if err != nil {
		t.Fatalf("runPolicyTest --verbose error: %v", err)
	}
	output := buf.String()
	// Verbose output should include the reason in parentheses.
	if !strings.Contains(output, "PASS: allow-read (") {
		t.Errorf("expected verbose PASS with reason; got: %s", output)
	}
}

func TestPolicyTestCommandRequiresFlags(t *testing.T) {
	err := runPolicyTest([]string{})
	if err == nil {
		t.Fatal("expected error when --policy and --tests are missing")
	}
}

// ── #33 / #34: --tamper-evident + audit verify ────────────────────────────────

// writeTamperEvidentLog runs `check --tamper-evident --audit-log <file>` and
// returns the audit file path. Fails the test if the command errors.
func writeTamperEvidentLog(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	policyFile := filepath.Join(dir, "policy.yaml")
	callFile := filepath.Join(dir, "calls.jsonl")
	auditFile := filepath.Join(dir, "audit.jsonl")

	writeTestFile(t, policyFile, []byte(`version: "0.1"
defaults:
  decision: deny
tools:
  filesystem.read:
    decision: allow
`))
	writeTestFile(t, callFile, []byte(
		`{"id":"c1","tool":"filesystem.read","arguments":{"path":"README.md"}}`+"\n"+
			`{"id":"c2","tool":"filesystem.read","arguments":{"path":"go.mod"}}`+"\n"+
			`{"id":"c3","tool":"filesystem.read","arguments":{"path":"main.go"}}`+"\n",
	))

	if err := runCheck([]string{
		"--policy", policyFile,
		"--call", callFile,
		"--audit-log", auditFile,
		"--output", "json",
		"--tamper-evident",
	}); err != nil {
		t.Fatalf("runCheck --tamper-evident error: %v", err)
	}
	return auditFile
}

func TestAuditVerifyHappyPath(t *testing.T) {
	auditFile := writeTamperEvidentLog(t)

	r, w, _ := os.Pipe()
	oldStdout := os.Stdout
	os.Stdout = w

	err := runAuditVerify([]string{"--log", auditFile})

	w.Close()
	os.Stdout = oldStdout
	var buf bytes.Buffer
	io.Copy(&buf, r)

	if err != nil {
		t.Fatalf("runAuditVerify error: %v\nstdout: %s", err, buf.String())
	}
	if !strings.Contains(buf.String(), "OK: 3 event(s) verified") {
		t.Errorf("expected 'OK: 3 event(s) verified', got: %s", buf.String())
	}
}

func TestAuditVerifyDetectsTampering(t *testing.T) {
	auditFile := writeTamperEvidentLog(t)

	// Tamper with the audit file: modify event 2's reason in place.
	contents, err := os.ReadFile(auditFile)
	if err != nil {
		t.Fatalf("read audit: %v", err)
	}
	tampered := bytes.Replace(contents, []byte(`"reason":"`), []byte(`"reason":"TAMPER:`), 1)
	if bytes.Equal(tampered, contents) {
		t.Fatal("test setup failed: nothing replaced")
	}
	if err := os.WriteFile(auditFile, tampered, 0o644); err != nil {
		t.Fatalf("rewrite audit: %v", err)
	}

	err = runAuditVerify([]string{"--log", auditFile})
	if err == nil {
		t.Fatal("expected runAuditVerify to detect tampering, got nil error")
	}
	if !strings.Contains(err.Error(), "event 1") {
		t.Errorf("expected error to reference event 1 (first event was tampered), got: %v", err)
	}
}

func TestAuditVerifyNonChainedLog(t *testing.T) {
	dir := t.TempDir()
	policyFile := filepath.Join(dir, "policy.yaml")
	callFile := filepath.Join(dir, "calls.jsonl")
	auditFile := filepath.Join(dir, "audit.jsonl")

	writeTestFile(t, policyFile, []byte(`version: "0.1"
defaults:
  decision: deny
tools:
  filesystem.read:
    decision: allow
`))
	writeTestFile(t, callFile, []byte(`{"id":"c1","tool":"filesystem.read","arguments":{"path":"README.md"}}`+"\n"))

	// Plain check without --tamper-evident.
	if err := runCheck([]string{
		"--policy", policyFile,
		"--call", callFile,
		"--audit-log", auditFile,
		"--output", "json",
	}); err != nil {
		t.Fatalf("runCheck: %v", err)
	}

	r, w, _ := os.Pipe()
	oldStdout := os.Stdout
	os.Stdout = w
	oldStderr := os.Stderr
	rerr, werr, _ := os.Pipe()
	os.Stderr = werr

	err := runAuditVerify([]string{"--log", auditFile})

	w.Close()
	werr.Close()
	os.Stdout = oldStdout
	os.Stderr = oldStderr
	var bout, berr bytes.Buffer
	io.Copy(&bout, r)
	io.Copy(&berr, rerr)

	if err != nil {
		t.Fatalf("runAuditVerify on non-chained log should not error, got: %v", err)
	}
	if !strings.Contains(berr.String(), "chained") && !strings.Contains(berr.String(), "tamper-evident") {
		t.Errorf("expected warning about non-chained log on stderr, got: %s", berr.String())
	}
	if !strings.Contains(bout.String(), "PARSED:") {
		t.Errorf("expected 'PARSED:' summary on stdout, got: %s", bout.String())
	}
}

func TestAuditVerifyRequiresLogFlag(t *testing.T) {
	if err := runAuditVerify([]string{}); err == nil {
		t.Fatal("expected error when --log is missing")
	}
}

func TestAuditSubcmdUnknown(t *testing.T) {
	if err := runAuditSubcmd([]string{"bogus"}); err == nil {
		t.Fatal("expected error for unknown audit subcommand")
	}
}

func TestAuditSubcmdRequiresSub(t *testing.T) {
	if err := runAuditSubcmd([]string{}); err == nil {
		t.Fatal("expected error when no audit subcommand given")
	}
}

// TestTamperEvidentWithoutAuditLogWarns verifies the warning path when
// --tamper-evident is used with no --audit-log destination.
func TestTamperEvidentWithoutAuditLogWarns(t *testing.T) {
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
	writeTestFile(t, callFile, []byte(`{"id":"c1","tool":"filesystem.read","arguments":{"path":"README.md"}}`+"\n"))

	oldStderr := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w
	// Quiet stdout for this test.
	oldStdout := os.Stdout
	devnull, _ := os.Open(os.DevNull)
	os.Stdout = devnull

	err := runCheck([]string{
		"--policy", policyFile,
		"--call", callFile,
		"--output", "json",
		"--tamper-evident",
	})

	w.Close()
	os.Stderr = oldStderr
	os.Stdout = oldStdout
	devnull.Close()
	var buf bytes.Buffer
	io.Copy(&buf, r)

	if err != nil {
		t.Fatalf("runCheck: %v", err)
	}
	if !strings.Contains(buf.String(), "warning") {
		t.Errorf("expected warning on stderr; got: %s", buf.String())
	}
}

// ── #29 / #30 / #40: approval and dry-run integration ────────────────────────

// askPolicyAndCall writes a minimal policy that returns ask for github.create_issue
// and a calls file with a single ask call. Returns the two paths.
func askPolicyAndCall(t *testing.T) (policyPath, callPath string) {
	t.Helper()
	dir := t.TempDir()
	policyPath = filepath.Join(dir, "policy.yaml")
	callPath = filepath.Join(dir, "calls.jsonl")
	writeTestFile(t, policyPath, []byte(`version: "0.1"
defaults:
  decision: deny
tools:
  github.create_issue:
    decision: ask
`))
	writeTestFile(t, callPath, []byte(`{"id":"c1","tool":"github.create_issue","arguments":{}}
`))
	return policyPath, callPath
}

// readAuditEvents parses every JSON object on its own line in path.
func readAuditEvents(t *testing.T, path string) []map[string]interface{} {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read audit log: %v", err)
	}
	var out []map[string]interface{}
	for _, line := range strings.Split(strings.TrimRight(string(b), "\n"), "\n") {
		if line == "" {
			continue
		}
		var m map[string]interface{}
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("invalid audit line %q: %v", line, err)
		}
		out = append(out, m)
	}
	return out
}

func TestCheckNoInteractiveAutoDeniesAsk(t *testing.T) {
	policyFile, callFile := askPolicyAndCall(t)
	dir := filepath.Dir(policyFile)
	auditFile := filepath.Join(dir, "audit.jsonl")

	if err := runCheck([]string{
		"--policy", policyFile,
		"--call", callFile,
		"--audit-log", auditFile,
		"--no-interactive",
	}); err != nil {
		t.Fatalf("runCheck: %v", err)
	}

	events := readAuditEvents(t, auditFile)
	if len(events) != 1 {
		t.Fatalf("expected 1 audit event, got %d", len(events))
	}
	if events[0]["decision"] != "deny" {
		t.Errorf("decision = %v, want deny", events[0]["decision"])
	}
	if got, want := events[0]["reason"], "non-interactive: ask auto-denied"; got != want {
		t.Errorf("reason = %v, want %q", got, want)
	}
	if _, hasMode := events[0]["mode"]; hasMode {
		t.Errorf("mode should be absent for enforced events; got %v", events[0]["mode"])
	}
}

func TestCheckDryRunPreservesAskAndMarksMode(t *testing.T) {
	policyFile, callFile := askPolicyAndCall(t)
	dir := filepath.Dir(policyFile)
	auditFile := filepath.Join(dir, "audit.jsonl")

	if err := runCheck([]string{
		"--policy", policyFile,
		"--call", callFile,
		"--audit-log", auditFile,
		"--dry-run",
	}); err != nil {
		t.Fatalf("runCheck: %v", err)
	}

	events := readAuditEvents(t, auditFile)
	if len(events) != 1 {
		t.Fatalf("expected 1 audit event, got %d", len(events))
	}
	if events[0]["decision"] != "ask" {
		t.Errorf("decision = %v, want ask (approver must not be invoked in dry-run)", events[0]["decision"])
	}
	if events[0]["mode"] != "dry_run" {
		t.Errorf("mode = %v, want dry_run", events[0]["mode"])
	}
	if events[0]["schema_version"] != "2" {
		t.Errorf("schema_version = %v, want 2", events[0]["schema_version"])
	}
}

func TestCheckDryRunSuppressesFailOnExit(t *testing.T) {
	// A denied call combined with --fail-on deny normally returns an error.
	// In --dry-run, the call is reported but the exit is not propagated.
	dir := t.TempDir()
	policyFile := filepath.Join(dir, "policy.yaml")
	callFile := filepath.Join(dir, "calls.jsonl")
	writeTestFile(t, policyFile, []byte(`version: "0.1"
defaults:
  decision: deny
`))
	writeTestFile(t, callFile, []byte(`{"id":"c1","tool":"shell.exec","arguments":{}}
`))

	if err := runCheck([]string{
		"--policy", policyFile,
		"--call", callFile,
		"--fail-on", "deny",
		"--dry-run",
	}); err != nil {
		t.Fatalf("dry-run should not propagate --fail-on exit, got: %v", err)
	}

	// Sanity: without --dry-run the same input does fail.
	if err := runCheck([]string{
		"--policy", policyFile,
		"--call", callFile,
		"--fail-on", "deny",
	}); err == nil {
		t.Fatal("expected --fail-on deny to error without --dry-run")
	}
}

func TestCheckApprovalTimeoutDeniesAsk(t *testing.T) {
	// Use a 1ms timeout; the default approver path tries to open /dev/tty,
	// so we force --no-interactive to keep the test deterministic — but
	// --no-interactive should NOT short-circuit timeout semantics for the
	// flag plumbing test. Instead, validate that --approval-timeout is
	// accepted and produces a deny decision either way.
	policyFile, callFile := askPolicyAndCall(t)
	dir := filepath.Dir(policyFile)
	auditFile := filepath.Join(dir, "audit.jsonl")

	if err := runCheck([]string{
		"--policy", policyFile,
		"--call", callFile,
		"--audit-log", auditFile,
		"--no-interactive",
		"--approval-timeout", "1ms",
	}); err != nil {
		t.Fatalf("runCheck: %v", err)
	}

	events := readAuditEvents(t, auditFile)
	if len(events) != 1 {
		t.Fatalf("expected 1 audit event, got %d", len(events))
	}
	if events[0]["decision"] != "deny" {
		t.Errorf("decision = %v, want deny", events[0]["decision"])
	}
}

func TestCheckRejectsInvalidApprovalTimeout(t *testing.T) {
	policyFile, callFile := askPolicyAndCall(t)
	err := runCheck([]string{
		"--policy", policyFile,
		"--call", callFile,
		"--approval-timeout", "nonsense",
	})
	if err == nil {
		t.Fatal("expected error on invalid --approval-timeout")
	}
}

func TestCheckDryRunTextOutputContainsMarker(t *testing.T) {
	policyFile, callFile := askPolicyAndCall(t)
	r, w, _ := os.Pipe()
	oldStdout := os.Stdout
	os.Stdout = w

	err := runCheck([]string{
		"--policy", policyFile,
		"--call", callFile,
		"--dry-run",
	})

	w.Close()
	os.Stdout = oldStdout
	var buf bytes.Buffer
	io.Copy(&buf, r)

	if err != nil {
		t.Fatalf("runCheck: %v", err)
	}
	if !strings.Contains(buf.String(), "[dry-run]") {
		t.Errorf("expected [dry-run] marker in text output; got:\n%s", buf.String())
	}
}

// TestRunProxyRequiresCommand verifies that omitting the downstream command
// produces a clear error pointing at the `--` convention.
func TestRunProxyRequiresCommand(t *testing.T) {
	err := runProxy([]string{"--policy", "/dev/null"})
	if err == nil {
		t.Fatal("expected error when downstream command is missing")
	}
	if !strings.Contains(err.Error(), "command is required") {
		t.Errorf("error message %q must mention the missing command", err.Error())
	}
}

// TestRunProxyRequiresPolicyUnlessPassthrough verifies the --policy/--passthrough
// invariant: enforcement-mode runs must point at a policy.
func TestRunProxyRequiresPolicyUnlessPassthrough(t *testing.T) {
	err := runProxy([]string{"--", "true"})
	if err == nil {
		t.Fatal("expected error when --policy is missing in enforcement mode")
	}
	if !strings.Contains(err.Error(), "--policy is required") {
		t.Errorf("error message %q must mention --policy", err.Error())
	}
}

// TestRunProxyRejectsMissingPolicyFile verifies that a non-existent policy
// path surfaces as a load error, not silently falls through to passthrough.
func TestRunProxyRejectsMissingPolicyFile(t *testing.T) {
	err := runProxy([]string{"--policy", filepath.Join(t.TempDir(), "nope.yaml"), "--", "true"})
	if err == nil {
		t.Fatal("expected error when --policy file does not exist")
	}
}
