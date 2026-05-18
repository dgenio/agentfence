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
