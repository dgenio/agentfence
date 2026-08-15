package policy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestToolActionDigestDeterministicExactSemantics(t *testing.T) {
	callA := ToolCall{
		ID:   "request-a",
		Tool: "filesystem.write",
		Arguments: map[string]interface{}{
			"path":   ".env",
			"count":  json.Number("9007199254740993"),
			"ratio":  json.Number("1.00"),
			"nested": map[string]interface{}{"b": "two", "a": "one"},
		},
	}
	callB := ToolCall{
		ID:   "request-b",
		Tool: "filesystem.write",
		Arguments: map[string]interface{}{
			"nested": map[string]interface{}{"a": "one", "b": "two"},
			"ratio":  json.Number("1.00"),
			"count":  json.Number("9007199254740993"),
			"path":   ".env",
		},
	}

	digestA, err := ToolActionDigest(callA)
	if err != nil {
		t.Fatalf("ToolActionDigest(callA) error = %v", err)
	}
	digestB, err := ToolActionDigest(callB)
	if err != nil {
		t.Fatalf("ToolActionDigest(callB) error = %v", err)
	}
	if digestA != digestB {
		t.Fatalf("map order/request ID changed digest: %q != %q", digestA, digestB)
	}
	if !strings.HasPrefix(digestA, ToolActionDigestAlgorithm+":sha256:") {
		t.Fatalf("digest = %q, want neutral versioned prefix", digestA)
	}
	if strings.Contains(strings.ToLower(digestA), "agentfence") || strings.Contains(strings.ToLower(digestA), "vericordon") {
		t.Fatalf("digest prefix must be brand-neutral: %q", digestA)
	}
}

func TestToolActionDigestDistinguishesExactChanges(t *testing.T) {
	base := ToolCall{Tool: "demo", Arguments: map[string]interface{}{"n": json.Number("1"), "items": []interface{}{"a", "b"}}}
	baseDigest, err := ToolActionDigest(base)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name string
		call ToolCall
	}{
		{"numeric lexical form", ToolCall{Tool: "demo", Arguments: map[string]interface{}{"n": json.Number("1.0"), "items": []interface{}{"a", "b"}}}},
		{"number versus string", ToolCall{Tool: "demo", Arguments: map[string]interface{}{"n": "1", "items": []interface{}{"a", "b"}}}},
		{"array order", ToolCall{Tool: "demo", Arguments: map[string]interface{}{"n": json.Number("1"), "items": []interface{}{"b", "a"}}}},
		{"tool", ToolCall{Tool: "other", Arguments: map[string]interface{}{"n": json.Number("1"), "items": []interface{}{"a", "b"}}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ToolActionDigest(tt.call)
			if err != nil {
				t.Fatalf("ToolActionDigest() error = %v", err)
			}
			if got == baseDigest {
				t.Fatalf("changed action retained digest %q", got)
			}
		})
	}
}

func TestToolActionDigestNormalizesAbsentArgumentsAndRejectsFloat(t *testing.T) {
	nilDigest, err := ToolActionDigest(ToolCall{Tool: "demo"})
	if err != nil {
		t.Fatal(err)
	}
	emptyDigest, err := ToolActionDigest(ToolCall{Tool: "demo", Arguments: map[string]interface{}{}})
	if err != nil {
		t.Fatal(err)
	}
	if nilDigest != emptyDigest {
		t.Fatalf("nil and empty arguments differ: %q != %q", nilDigest, emptyDigest)
	}

	if _, err := ToolActionDigest(ToolCall{Tool: "demo", Arguments: map[string]interface{}{"n": float64(9007199254740993)}}); err == nil {
		t.Fatal("ToolActionDigest accepted float64 authorization input")
	}
}

func TestEffectivePolicyDigestNormalizesFormattingDefaultsAndImports(t *testing.T) {
	directYAML := []byte(`version: "0.1"
defaults:
  decision: deny
tools:
  demo:
    decision: allow
`)
	formattedYAML := []byte(`# same policy, different source formatting
version: "0.1"
defaults: {decision: deny}
tools: {demo: {decision: allow}}
audit:
  format: jsonl
`)

	direct, err := ParsePolicy(directYAML)
	if err != nil {
		t.Fatal(err)
	}
	formatted, err := ParsePolicy(formattedYAML)
	if err != nil {
		t.Fatal(err)
	}
	directDigest, err := EffectivePolicyDigest(direct)
	if err != nil {
		t.Fatal(err)
	}
	formattedDigest, err := EffectivePolicyDigest(formatted)
	if err != nil {
		t.Fatal(err)
	}
	if directDigest != formattedDigest {
		t.Fatalf("formatting/explicit defaults changed digest: %q != %q", directDigest, formattedDigest)
	}

	dir := t.TempDir()
	child := filepath.Join(dir, "child.yaml")
	root := filepath.Join(dir, "root.yaml")
	if err := os.WriteFile(child, []byte(`version: "0.1"
tools:
  demo:
    decision: allow
`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(root, []byte(`version: "0.1"
imports:
  - child.yaml
defaults:
  decision: deny
`), 0o600); err != nil {
		t.Fatal(err)
	}
	imported, err := LoadFile(root)
	if err != nil {
		t.Fatal(err)
	}
	importedDigest, err := EffectivePolicyDigest(imported)
	if err != nil {
		t.Fatal(err)
	}
	if importedDigest != directDigest {
		t.Fatalf("equivalent resolved import graph changed digest: %q != %q", importedDigest, directDigest)
	}
}

func TestEffectivePolicyDigestChangesWithEffectivePolicyAndRejectsUnresolved(t *testing.T) {
	base, err := ParsePolicy([]byte(`version: "0.1"
tools:
  demo:
    decision: allow
`))
	if err != nil {
		t.Fatal(err)
	}
	changed, err := ParsePolicy([]byte(`version: "0.1"
tools:
  demo:
    decision: deny
`))
	if err != nil {
		t.Fatal(err)
	}
	baseDigest, err := EffectivePolicyDigest(base)
	if err != nil {
		t.Fatal(err)
	}
	changedDigest, err := EffectivePolicyDigest(changed)
	if err != nil {
		t.Fatal(err)
	}
	if baseDigest == changedDigest {
		t.Fatalf("effective rule change retained digest %q", baseDigest)
	}
	if !strings.HasPrefix(baseDigest, ResolvedPolicyDigestAlgorithm+":sha256:") {
		t.Fatalf("digest = %q, want neutral versioned prefix", baseDigest)
	}

	unresolved := base
	unresolved.Imports = []string{"child.yaml"}
	if _, err := EffectivePolicyDigest(unresolved); err == nil {
		t.Fatal("EffectivePolicyDigest accepted unresolved imports")
	}

	invalid := base
	invalid.Defaults.Decision = Decision("maybe")
	if _, err := EffectivePolicyDigest(invalid); err == nil {
		t.Fatal("EffectivePolicyDigest accepted malformed policy")
	}
}
