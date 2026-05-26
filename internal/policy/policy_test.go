package policy

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParsePolicy(t *testing.T) {
	p, err := ParsePolicy([]byte(StarterPolicyYAML))
	if err != nil {
		t.Fatalf("ParsePolicy() error = %v", err)
	}
	if p.Defaults.Decision != DecisionDeny {
		t.Fatalf("expected default deny, got %s", p.Defaults.Decision)
	}
	if p.Tools["github.create_issue"].Decision != DecisionAsk {
		t.Fatalf("expected ask for github.create_issue")
	}
}

func TestParseToolCall(t *testing.T) {
	call, err := ParseToolCall([]byte(`{"id":"call_1","tool":"filesystem.read","arguments":{"path":"README.md"}}`))
	if err != nil {
		t.Fatalf("ParseToolCall() error = %v", err)
	}
	if call.Tool != "filesystem.read" {
		t.Fatalf("expected filesystem.read, got %s", call.Tool)
	}
}

func TestAuditFormatDefaultsToJsonl(t *testing.T) {
	p, err := ParsePolicy([]byte(`version: "0.1"
defaults:
  decision: deny
`))
	if err != nil {
		t.Fatalf("ParsePolicy() error = %v", err)
	}
	if p.Audit.Format != "jsonl" {
		t.Fatalf("expected audit.format to default to jsonl, got %q", p.Audit.Format)
	}
}

func TestAuditFormatRejectsUnsupported(t *testing.T) {
	_, err := ParsePolicy([]byte(`version: "0.1"
defaults:
  decision: deny
audit:
  format: xml
`))
	if err == nil {
		t.Fatal("expected error for unsupported audit format, got nil")
	}
}

// TestValidateStrict covers the strict schema-plus-semantic validation added
// by ValidateStrict.
func TestValidateStrict(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantCount int    // expected number of ValidationErrors
		wantMsg   string // substring expected in at least one error message
	}{
		{
			name: "valid policy",
			input: `version: "0.1"
defaults:
  decision: deny
`,
			wantCount: 0,
		},
		{
			name: "unknown field typo",
			input: `version: "0.1"
defaults:
  decisoin: deny
`,
			wantCount: 1,
			wantMsg:   "decisoin",
		},
		{
			name: "invalid decision value",
			input: `version: "0.1"
defaults:
  decision: maybe
`,
			wantCount: 1,
			wantMsg:   "must be one of allow, deny, ask",
		},
		{
			name: "invalid redaction regex",
			input: `version: "0.1"
defaults:
  decision: deny
redaction:
  enabled: true
  patterns:
    - name: bad_regex
      regex: "[invalid"
`,
			wantCount: 1,
			wantMsg:   "invalid regex",
		},
		{
			name: "missing version",
			input: `defaults:
  decision: deny
`,
			wantCount: 1,
			wantMsg:   "version field is required",
		},
		{
			name: "invalid tool decision",
			input: `version: "0.1"
defaults:
  decision: deny
tools:
  my.tool:
    decision: sure
`,
			wantCount: 1,
			wantMsg:   "must be one of allow, deny, ask",
		},
		{
			name: "invalid audit format",
			input: `version: "0.1"
defaults:
  decision: deny
audit:
  format: xml
`,
			wantCount: 1,
			wantMsg:   "unsupported format",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errs := ValidateStrict([]byte(tt.input))
			if len(errs) != tt.wantCount {
				t.Fatalf("ValidateStrict() got %d error(s), want %d: %v", len(errs), tt.wantCount, errs)
			}
			if tt.wantMsg != "" && tt.wantCount > 0 {
				found := false
				for _, e := range errs {
					if strings.Contains(e.Error(), tt.wantMsg) {
						found = true
						break
					}
				}
				if !found {
					t.Fatalf("ValidateStrict() errors %v do not contain %q", errs, tt.wantMsg)
				}
			}
		})
	}
}

// TestParseGroupsInPolicy verifies that the groups key is parsed correctly.
func TestParseGroupsInPolicy(t *testing.T) {
	p, err := ParsePolicy([]byte(`version: "0.1"
defaults:
  decision: deny
groups:
  fs-tools:
    - filesystem.read
    - filesystem.*
tools:
  fs-tools:
    decision: ask
`))
	if err != nil {
		t.Fatalf("ParsePolicy error: %v", err)
	}
	if len(p.Groups) == 0 {
		t.Fatal("expected groups to be parsed")
	}
	members := p.Groups["fs-tools"]
	if len(members) != 2 {
		t.Fatalf("expected 2 group members, got %d", len(members))
	}
}

// TestParsePolicyTestFixture verifies that test fixture YAML is parsed correctly.
func TestParsePolicyTestFixture(t *testing.T) {
	fixture, err := ParsePolicyTestFixture([]byte(`tests:
  - id: allow-readme
    tool: filesystem.read
    arguments:
      path: README.md
    expect: allow
  - id: deny-env
    tool: filesystem.write
    arguments:
      path: .env
    expect: deny
`))
	if err != nil {
		t.Fatalf("ParsePolicyTestFixture error: %v", err)
	}
	if len(fixture.Tests) != 2 {
		t.Fatalf("expected 2 tests, got %d", len(fixture.Tests))
	}
	if fixture.Tests[0].ID != "allow-readme" {
		t.Fatalf("expected first test id 'allow-readme', got %q", fixture.Tests[0].ID)
	}
	if fixture.Tests[0].Expect != DecisionAllow {
		t.Fatalf("expected first test expect 'allow', got %q", fixture.Tests[0].Expect)
	}
}

// TestParsePolicyTestFixtureMissingID verifies that a test without an id returns an error.
func TestParsePolicyTestFixtureMissingID(t *testing.T) {
	_, err := ParsePolicyTestFixture([]byte(`tests:
  - tool: filesystem.read
    arguments:
      path: README.md
    expect: allow
`))
	if err == nil {
		t.Fatal("expected error for missing id, got nil")
	}
}

// TestParsePolicyTestFixtureInvalidExpect verifies that an invalid expect value returns an error.
func TestParsePolicyTestFixtureInvalidExpect(t *testing.T) {
	_, err := ParsePolicyTestFixture([]byte(`tests:
  - id: bad-test
    tool: filesystem.read
    expect: maybe
`))
	if err == nil {
		t.Fatal("expected error for invalid expect value, got nil")
	}
}

// TestParsePolicyTestFixtureEmpty verifies that an empty fixture returns an error.
func TestParsePolicyTestFixtureEmpty(t *testing.T) {
	_, err := ParsePolicyTestFixture([]byte(`tests: []`))
	if err == nil {
		t.Fatal("expected error for empty fixture, got nil")
	}
}

// writeFile writes content to t.TempDir()/name and returns the absolute path.
func writeFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return p
}

// TestPolicyImportsBasic verifies that imports are resolved and merged with
// importing-policy-wins semantics on key conflicts.
func TestPolicyImportsBasic(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "base.yaml", `version: "0.1"
defaults:
  decision: deny
tools:
  github.delete_repo:
    decision: deny
  filesystem.read:
    decision: deny
`)
	root := writeFile(t, dir, "root.yaml", `version: "0.1"
imports:
  - base.yaml
tools:
  filesystem.read:
    decision: allow
`)
	p, err := LoadFile(root)
	if err != nil {
		t.Fatalf("LoadFile error: %v", err)
	}
	if got := p.Tools["filesystem.read"].Decision; got != DecisionAllow {
		t.Errorf("filesystem.read: importing rule should win; got %q want allow", got)
	}
	if got := p.Tools["github.delete_repo"].Decision; got != DecisionDeny {
		t.Errorf("github.delete_repo: inherited rule lost; got %q want deny", got)
	}
	if p.Imports != nil {
		t.Errorf("Imports field should be cleared after resolution; got %v", p.Imports)
	}
}

// TestPolicyImportsRedactionUnion verifies redaction patterns from imported
// files are unioned with the importing file's patterns.
func TestPolicyImportsRedactionUnion(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "base.yaml", `version: "0.1"
defaults:
  decision: deny
redaction:
  enabled: true
  patterns:
    - name: base_pat
      regex: "BASE-[A-Z0-9]+"
`)
	root := writeFile(t, dir, "root.yaml", `version: "0.1"
imports:
  - base.yaml
redaction:
  patterns:
    - name: root_pat
      regex: "ROOT-[A-Z0-9]+"
`)
	p, err := LoadFile(root)
	if err != nil {
		t.Fatalf("LoadFile error: %v", err)
	}
	names := make([]string, 0, len(p.Redaction.Patterns))
	for _, pat := range p.Redaction.Patterns {
		names = append(names, pat.Name)
	}
	if len(names) != 2 {
		t.Fatalf("expected 2 patterns after merge, got %d (%v)", len(names), names)
	}
	if names[0] != "base_pat" || names[1] != "root_pat" {
		t.Errorf("expected [base_pat, root_pat] in order; got %v", names)
	}
	if !p.Redaction.Enabled {
		t.Error("redaction.enabled should be true after OR merge")
	}
}

// TestPolicyImportsCircular verifies that a cycle is detected and reported.
func TestPolicyImportsCircular(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "a.yaml", `version: "0.1"
imports:
  - b.yaml
`)
	writeFile(t, dir, "b.yaml", `version: "0.1"
imports:
  - a.yaml
`)
	_, err := LoadFile(filepath.Join(dir, "a.yaml"))
	if err == nil {
		t.Fatal("expected circular import error, got nil")
	}
	if !strings.Contains(err.Error(), "circular") {
		t.Errorf("expected circular-import error, got: %v", err)
	}
}

// TestPolicyImportsDepthLimit verifies that nesting deeper than MaxImportDepth
// is rejected.
func TestPolicyImportsDepthLimit(t *testing.T) {
	dir := t.TempDir()
	// Build a chain root → l1 → l2 → l3 → l4. Root + 4 levels = depth 4 → reject.
	writeFile(t, dir, "l4.yaml", `version: "0.1"
defaults:
  decision: deny
`)
	for i := 3; i >= 1; i-- {
		writeFile(t, dir, fmt.Sprintf("l%d.yaml", i), fmt.Sprintf(`version: "0.1"
imports:
  - l%d.yaml
`, i+1))
	}
	root := writeFile(t, dir, "root.yaml", `version: "0.1"
imports:
  - l1.yaml
`)
	_, err := LoadFile(root)
	if err == nil {
		t.Fatal("expected depth-limit error, got nil")
	}
	if !strings.Contains(err.Error(), "depth") {
		t.Errorf("expected depth-limit error, got: %v", err)
	}
}

// TestPolicyImportsPathEscape verifies that imports outside the importing
// file's directory are rejected.
func TestPolicyImportsPathEscape(t *testing.T) {
	dir := t.TempDir()
	root := writeFile(t, dir, "root.yaml", `version: "0.1"
imports:
  - ../escape.yaml
`)
	_, err := LoadFile(root)
	if err == nil {
		t.Fatal("expected escape-rejection error, got nil")
	}
	if !strings.Contains(err.Error(), "escapes") {
		t.Errorf("expected directory-escape error, got: %v", err)
	}
}

// TestPolicyImportsSymlinkEscape verifies that imports cannot escape the
// importing directory through symlinks that point outside that directory.
func TestPolicyImportsSymlinkEscape(t *testing.T) {
	dir := t.TempDir()
	outside := t.TempDir()
	target := writeFile(t, outside, "escape.yaml", `version: "0.1"
defaults:
  decision: allow
`)
	link := filepath.Join(dir, "escape-link.yaml")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks unavailable on this platform/configuration: %v", err)
	}
	root := writeFile(t, dir, "root.yaml", `version: "0.1"
imports:
  - escape-link.yaml
`)
	_, err := LoadFile(root)
	if err == nil {
		t.Fatal("expected symlink escape rejection, got nil")
	}
	if !strings.Contains(err.Error(), "escapes") {
		t.Errorf("expected directory-escape error, got: %v", err)
	}
}

// TestPolicyImportsAbsoluteRejected verifies absolute import paths are rejected.
func TestPolicyImportsAbsoluteRejected(t *testing.T) {
	dir := t.TempDir()
	root := writeFile(t, dir, "root.yaml", `version: "0.1"
imports:
  - /etc/passwd
`)
	_, err := LoadFile(root)
	if err == nil {
		t.Fatal("expected absolute-import rejection, got nil")
	}
	if !strings.Contains(err.Error(), "absolute") {
		t.Errorf("expected absolute-path error, got: %v", err)
	}
}

// TestPolicyImportsSiblingOrder verifies that two sibling imports defining the
// same tool key resolve to the later import (later wins).
func TestPolicyImportsSiblingOrder(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "first.yaml", `version: "0.1"
tools:
  shared.tool:
    decision: allow
`)
	writeFile(t, dir, "second.yaml", `version: "0.1"
tools:
  shared.tool:
    decision: deny
`)
	root := writeFile(t, dir, "root.yaml", `version: "0.1"
imports:
  - first.yaml
  - second.yaml
`)
	p, err := LoadFile(root)
	if err != nil {
		t.Fatalf("LoadFile error: %v", err)
	}
	if got := p.Tools["shared.tool"].Decision; got != DecisionDeny {
		t.Errorf("expected later sibling to win (deny); got %q", got)
	}
}

// TestPolicyImportsRootOverridesImports verifies that an explicit rule in the
// importing file overrides any sibling import that defines the same key.
func TestPolicyImportsRootOverridesImports(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "base.yaml", `version: "0.1"
tools:
  shared.tool:
    decision: deny
`)
	root := writeFile(t, dir, "root.yaml", `version: "0.1"
imports:
  - base.yaml
tools:
  shared.tool:
    decision: ask
`)
	p, err := LoadFile(root)
	if err != nil {
		t.Fatalf("LoadFile error: %v", err)
	}
	if got := p.Tools["shared.tool"].Decision; got != DecisionAsk {
		t.Errorf("expected importing file to override; got %q want ask", got)
	}
}

// TestPolicyImportsMissingFile verifies a clear error when an import doesn't exist.
func TestPolicyImportsMissingFile(t *testing.T) {
	dir := t.TempDir()
	root := writeFile(t, dir, "root.yaml", `version: "0.1"
imports:
  - missing.yaml
`)
	_, err := LoadFile(root)
	if err == nil {
		t.Fatal("expected error for missing import, got nil")
	}
}

// TestMemoryWriteConstraintValidation verifies invalid memory_write values
// surface through ParsePolicy and ValidateStrict.
func TestMemoryWriteConstraintValidation(t *testing.T) {
	cases := []struct {
		name    string
		yaml    string
		wantErr string
	}{
		{
			name: "invalid max_scope",
			yaml: `version: "0.1"
tools:
  memory.write:
    decision: ask
    constraints:
      memory_write:
        max_scope: cluster
`,
			wantErr: "max_scope",
		},
		{
			name: "invalid max_sensitivity",
			yaml: `version: "0.1"
tools:
  memory.write:
    decision: ask
    constraints:
      memory_write:
        max_sensitivity: extreme
`,
			wantErr: "max_sensitivity",
		},
		{
			name: "negative max_bytes",
			yaml: `version: "0.1"
tools:
  memory.write:
    decision: ask
    constraints:
      memory_write:
        max_bytes: -1
`,
			wantErr: "max_bytes",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParsePolicy([]byte(tc.yaml))
			if err == nil {
				t.Fatalf("expected error mentioning %q, got nil", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("expected error to mention %q, got: %v", tc.wantErr, err)
			}
		})
	}
}

// TestMemoryWriteConstraintParsing verifies the constraint round-trips
// through ParsePolicy when valid.
func TestMemoryWriteConstraintParsing(t *testing.T) {
	p, err := ParsePolicy([]byte(`version: "0.1"
tools:
  memory.write:
    decision: ask
    constraints:
      memory_write:
        max_scope: project
        max_sensitivity: medium
        max_bytes: 1024
        payload_fields:
          - value
`))
	if err != nil {
		t.Fatalf("ParsePolicy error: %v", err)
	}
	mw := p.Tools["memory.write"].Constraints.MemoryWrite
	if !mw.IsSet() {
		t.Fatal("expected MemoryWrite.IsSet() = true")
	}
	if mw.MaxScope != "project" || mw.MaxSensitivity != "medium" || mw.MaxBytes != 1024 {
		t.Errorf("unexpected values: %+v", mw)
	}
	if len(mw.PayloadFields) != 1 || mw.PayloadFields[0] != "value" {
		t.Errorf("expected PayloadFields=[value]; got %v", mw.PayloadFields)
	}
}

// TestMemoryScopeRank and TestMemorySensitivityRank verify the ordering
// helpers used by the engine.
func TestMemoryScopeAndSensitivityRanks(t *testing.T) {
	if MemoryScopeRank("session") != 0 || MemoryScopeRank("project") != 1 || MemoryScopeRank("global") != 2 {
		t.Errorf("scope ranks wrong: session=%d project=%d global=%d",
			MemoryScopeRank("session"), MemoryScopeRank("project"), MemoryScopeRank("global"))
	}
	if MemoryScopeRank("cluster") != -1 {
		t.Errorf("unknown scope should rank -1, got %d", MemoryScopeRank("cluster"))
	}
	if MemorySensitivityRank("low") != 0 || MemorySensitivityRank("medium") != 1 || MemorySensitivityRank("high") != 2 {
		t.Errorf("sensitivity ranks wrong")
	}
	if MemorySensitivityRank("") != -1 {
		t.Errorf("empty sensitivity should rank -1")
	}
}
