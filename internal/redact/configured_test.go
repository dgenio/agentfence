package redact

import (
	"strings"
	"testing"

	"github.com/dgenio/agentfence/internal/policy"
)

func TestRedactArgumentsConfiguredTreatsPatternNameAsLiteralMarker(t *testing.T) {
	r, err := New(policy.RedactionConfig{
		Enabled: false,
		Patterns: []policy.RedactionPattern{{
			Name:  "$1",
			Regex: `(super-secret-value)`,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}

	got := r.RedactArgumentsConfigured(map[string]interface{}{"token": "super-secret-value"})
	value, ok := got["token"].(string)
	if !ok {
		t.Fatalf("redacted token type = %T, want string", got["token"])
	}
	if strings.Contains(value, "super-secret-value") {
		t.Fatalf("configured marker expanded regexp capture and leaked secret: %q", value)
	}
	if value != "[REDACTED:$1]" {
		t.Fatalf("redacted value = %q, want literal marker", value)
	}
}
