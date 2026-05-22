package policy

import (
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

func TestParsePolicyRejectsUnknownFields(t *testing.T) {
	tests := []struct {
		name string
		yaml string
		want string
	}{
		{
			name: "top level",
			yaml: `version: "0.1"
defaultz:
  decision: deny
`,
			want: "defaultz",
		},
		{
			name: "path constraints",
			yaml: `version: "0.1"
defaults:
  decision: deny
tools:
  filesystem.read:
    decision: allow
    constraints:
      paths:
        allowwww: ["./"]
`,
			want: "allowwww",
		},
		{
			name: "argument constraints",
			yaml: `version: "0.1"
defaults:
  decision: deny
tools:
  github.create_issue:
    decision: ask
    constraints:
      args:
        title:
          allowwww: ["bug*"]
`,
			want: "allowwww",
		},
		{
			name: "url constraints",
			yaml: `version: "0.1"
defaults:
  decision: deny
tools:
  browser.open:
    decision: allow
    constraints:
      urls:
        domainz: ["example.com"]
`,
			want: "domainz",
		},
		{
			name: "command constraints",
			yaml: `version: "0.1"
defaults:
  decision: deny
tools:
  shell.exec:
    decision: allow
    constraints:
      command:
        executablez: ["git"]
`,
			want: "executablez",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParsePolicy([]byte(tt.yaml))
			if err == nil {
				t.Fatal("ParsePolicy() expected unknown-field error, got nil")
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("ParsePolicy() error %q does not contain %q", err, tt.want)
			}
		})
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
