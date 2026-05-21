package redact

import (
	"encoding/json"
	"testing"

	"github.com/dgenio/agentfence/internal/policy"
)

// FuzzRedactArguments feeds arbitrary JSON-decoded maps to RedactArguments and
// asserts the redactor never panics. Tool-call arguments arrive as
// map[string]interface{} after JSON unmarshalling, so the fuzzer marshals
// random bytes into a wrapping object, unmarshals them back, and then feeds
// the resulting map to the redactor — this matches the real call shape and
// covers deeply nested structures, mixed types, and null leaves.
func FuzzRedactArguments(f *testing.F) {
	f.Add([]byte(`{"path":"README.md"}`))
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"k":null}`))
	f.Add([]byte(`{"k":["a","b","c"]}`))
	f.Add([]byte(`{"k":{"nested":{"deeper":"sk-demo-secret"}}}`))
	f.Add([]byte(`{"k":42,"l":true,"m":3.14}`))
	// String that the default redaction pattern would match if enabled.
	f.Add([]byte(`{"content":"OPENAI_API_KEY=sk-demo-secret"}`))

	// Build a redactor with a representative pattern so the regex branch is
	// exercised. A redactor with no patterns is the trivial pass-through case
	// and exercising it would not add coverage.
	red, err := New(policy.RedactionConfig{
		Enabled: true,
		Patterns: []policy.RedactionPattern{
			{Name: "openai_key", Regex: `sk-[A-Za-z0-9_-]+`},
			{Name: "github_token", Regex: `ghp_[A-Za-z0-9]+`},
		},
	})
	if err != nil {
		f.Fatalf("New() error = %v", err)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 16*1024 {
			t.Skip()
		}
		var m map[string]interface{}
		if err := json.Unmarshal(data, &m); err != nil {
			t.Skip()
		}
		_ = red.RedactArguments(m)
	})
}
