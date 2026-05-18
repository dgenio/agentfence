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
