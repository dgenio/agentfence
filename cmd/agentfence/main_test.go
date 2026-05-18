package main

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

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

	os.WriteFile("agentfence.yaml", []byte("existing"), 0o644)

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
	os.WriteFile(policyFile, []byte(`version: "0.1"
defaults:
  decision: deny
`), 0o644)
	os.WriteFile(callFile, []byte(""), 0o644)

	err := runCheck([]string{"--policy", policyFile, "--call", callFile, "--output", "xml"})
	if err == nil {
		t.Fatal("expected error for unknown --output mode 'xml'")
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

// TestCheckAllMalformedReturnsError verifies that an all-malformed input is
// treated as an error (no calls were evaluated).
func TestCheckAllMalformedReturnsError(t *testing.T) {
	dir := t.TempDir()
	policyFile := filepath.Join(dir, "policy.yaml")
	callFile := filepath.Join(dir, "calls.jsonl")

	os.WriteFile(policyFile, []byte(`version: "0.1"
defaults:
  decision: deny
`), 0o644)
	os.WriteFile(callFile, []byte("not json\nalso not json\n"), 0o644)

	err := runCheck([]string{"--policy", policyFile, "--call", callFile})
	if err == nil {
		t.Fatal("expected error when all lines fail to parse")
	}
}
