package policy

import (
	"strings"
	"testing"
)

// These tests pin the parser's behavior on edge-case inputs so the
// strict-parsing contract documented in docs/policy-language.md
// ("Parsing edge cases") is fully specified and cannot regress silently.

// An empty, whitespace-only (spaces/newlines), or comment-only file parses to
// an empty policy with defaults applied (default-deny) rather than erroring.
// Such a policy gates nothing explicitly; `validate` flags the missing version.
func TestParseBlankPolicyIsEmptyDefaultDeny(t *testing.T) {
	cases := map[string]string{
		"empty":        "",
		"spaces":       "   \n  \n",
		"newlines":     "\n\n\n",
		"comment only": "# just a comment\n",
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			p, err := ParsePolicy([]byte(in))
			if err != nil {
				t.Fatalf("ParsePolicy(%q) error = %v, want nil", in, err)
			}
			if p.Defaults.Decision != DecisionDeny {
				t.Fatalf("defaults.decision = %q, want %q", p.Defaults.Decision, DecisionDeny)
			}
			if len(p.Tools) != 0 {
				t.Fatalf("tools = %d, want 0", len(p.Tools))
			}
			// validate must still flag the missing version field.
			errs := ValidateStrict([]byte(in))
			if len(errs) == 0 {
				t.Fatalf("ValidateStrict(%q) returned no errors; expected a missing-version error", in)
			}
			joined := joinErrs(errs)
			if !strings.Contains(joined, "version") {
				t.Fatalf("ValidateStrict errors = %q, want one mentioning %q", joined, "version")
			}
		})
	}
}

// A tab character cannot start a YAML token; such input is a hard parse error
// rather than being silently treated as blank.
func TestParseTabIndentationRejected(t *testing.T) {
	if _, err := ParsePolicy([]byte("\t\n")); err == nil {
		t.Fatal("ParsePolicy of tab-only input = nil error, want a YAML error")
	}
}

// A file containing more than one YAML document is rejected: a policy file must
// contain exactly one document so a second document cannot shadow the first.
func TestParseMultiDocumentRejected(t *testing.T) {
	in := `version: "0.1"
---
version: "0.2"
`
	_, err := ParsePolicy([]byte(in))
	if err == nil {
		t.Fatal("ParsePolicy of multi-document input = nil error, want rejection")
	}
	if !strings.Contains(err.Error(), "single YAML document") {
		t.Fatalf("error = %q, want it to mention %q", err.Error(), "single YAML document")
	}
	if errs := ValidateStrict([]byte(in)); len(errs) == 0 {
		t.Fatal("ValidateStrict of multi-document input returned no errors")
	}
}

// Duplicate mapping keys are rejected by the strict decoder, both at the top
// level and inside the tools map, so a later key cannot silently override an
// earlier one without the author noticing.
func TestParseDuplicateKeysRejected(t *testing.T) {
	cases := map[string]string{
		"duplicate top-level key": `version: "0.1"
version: "0.2"
`,
		"duplicate tool key": `version: "0.1"
tools:
  a.b:
    decision: allow
  a.b:
    decision: deny
`,
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ParsePolicy([]byte(in)); err == nil {
				t.Fatalf("ParsePolicy(%s) = nil error, want a duplicate-key rejection", name)
			}
			if errs := ValidateStrict([]byte(in)); len(errs) == 0 {
				t.Fatalf("ValidateStrict(%s) returned no errors, want a duplicate-key rejection", name)
			}
		})
	}
}

func joinErrs(errs []ValidationError) string {
	parts := make([]string, 0, len(errs))
	for _, e := range errs {
		parts = append(parts, e.Error())
	}
	return strings.Join(parts, "; ")
}
