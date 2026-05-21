package redact

import (
	"strings"
	"testing"

	"github.com/dgenio/agentfence/internal/policy"
)

func TestRedactArguments(t *testing.T) {
	r, err := New(policy.RedactionConfig{
		Enabled: true,
		Patterns: []policy.RedactionPattern{
			{Name: "generic_secret_assignment", Regex: `(?i)(api_key|token|secret|password)\s*[:=]\s*[^\s]+`},
		},
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	args := map[string]interface{}{
		"content": "OPENAI_API_KEY=sk-demo-secret",
	}
	redacted := r.RedactArguments(args)
	content, ok := redacted["content"].(string)
	if !ok {
		t.Fatalf("redacted content type = %T", redacted["content"])
	}
	if strings.Contains(content, "sk-demo-secret") {
		t.Fatalf("expected secret to be redacted, got %s", content)
	}
}

func TestRedactDisabled(t *testing.T) {
	r, err := New(policy.RedactionConfig{
		Enabled: false,
		Patterns: []policy.RedactionPattern{
			{Name: "test", Regex: `secret`},
		},
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	args := map[string]interface{}{"key": "secret-value"}
	redacted := r.RedactArguments(args)
	if redacted["key"] != "secret-value" {
		t.Fatalf("expected no redaction when disabled, got %v", redacted["key"])
	}
}

func TestRedactNilArgs(t *testing.T) {
	r, err := New(policy.RedactionConfig{Enabled: true})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	redacted := r.RedactArguments(nil)
	if redacted != nil {
		t.Fatalf("expected nil for nil args, got %v", redacted)
	}
}

// TestMatchesAnyAndMatchedPatternNames verifies the payload-classification
// helpers used by the memory-write evaluator.
func TestMatchesAnyAndMatchedPatternNames(t *testing.T) {
	r, err := New(policy.RedactionConfig{
		Enabled: true,
		Patterns: []policy.RedactionPattern{
			{Name: "openai_api_key", Regex: `sk-[A-Za-z0-9_-]{20,}`},
			{Name: "github_token", Regex: `gh[pousr]_[A-Za-z0-9_]{20,}`},
		},
	})
	if err != nil {
		t.Fatalf("New error: %v", err)
	}

	if r.MatchesAny("just a benign string") {
		t.Error("benign string should not match")
	}
	if !r.MatchesAny("token sk-abcdef0123456789ABCDEF") {
		t.Error("OpenAI-shaped key should match")
	}
	names := r.MatchedPatternNames("ghp_aaaaaaaaaaaaaaaaaaaaaa and sk-bbbbbbbbbbbbbbbbbbbbbb")
	if len(names) != 2 {
		t.Fatalf("expected 2 matches, got %v", names)
	}
	// Names are returned in configuration order.
	if names[0] != "openai_api_key" || names[1] != "github_token" {
		t.Errorf("expected [openai_api_key, github_token]; got %v", names)
	}
}

// TestMatchesAnyDisabled verifies the helpers respect the disabled flag.
func TestMatchesAnyDisabled(t *testing.T) {
	r, err := New(policy.RedactionConfig{
		Enabled: false,
		Patterns: []policy.RedactionPattern{
			{Name: "p", Regex: `secret`},
		},
	})
	if err != nil {
		t.Fatalf("New error: %v", err)
	}
	if r.MatchesAny("secret") {
		t.Error("disabled redactor must not match")
	}
	if r.MatchedPatternNames("secret") != nil {
		t.Error("disabled redactor must return nil pattern names")
	}
}

// TestFingerprintPayload verifies the fingerprint is deterministic and short.
func TestFingerprintPayload(t *testing.T) {
	a := FingerprintPayload("hello")
	b := FingerprintPayload("hello")
	c := FingerprintPayload("world")
	if a != b {
		t.Errorf("fingerprint must be deterministic; got %q and %q", a, b)
	}
	if a == c {
		t.Error("different inputs must produce different fingerprints")
	}
	if len(a) != 12 {
		t.Errorf("fingerprint should be 12 hex chars, got %d (%q)", len(a), a)
	}
	if strings.ContainsAny(a, "ghijklmnopqrstuvwxyz") {
		t.Errorf("fingerprint should be hex; got %q", a)
	}
}

func TestRedactNestedStructures(t *testing.T) {
	r, err := New(policy.RedactionConfig{
		Enabled: true,
		Patterns: []policy.RedactionPattern{
			{Name: "token", Regex: `ghp_[A-Za-z0-9]+`},
		},
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	args := map[string]interface{}{
		"nested": map[string]interface{}{
			"token": "ghp_abc123def456",
		},
		"list": []interface{}{"ghp_secret789", "safe-value"},
	}
	redacted := r.RedactArguments(args)
	nested := redacted["nested"].(map[string]interface{})
	if strings.Contains(nested["token"].(string), "ghp_") {
		t.Fatalf("expected nested token to be redacted, got %s", nested["token"])
	}
	list := redacted["list"].([]interface{})
	if strings.Contains(list[0].(string), "ghp_") {
		t.Fatalf("expected list item to be redacted, got %s", list[0])
	}
	if list[1] != "safe-value" {
		t.Fatalf("expected safe value unchanged, got %s", list[1])
	}
}
