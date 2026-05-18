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
