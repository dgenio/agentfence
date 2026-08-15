package policy

import (
	"encoding/json"
	"testing"
)

func TestSnapshotToolCallDeepCopiesExactArguments(t *testing.T) {
	call := ToolCall{
		ID:   "call-1",
		Tool: "demo.tool",
		Arguments: map[string]interface{}{
			"n": json.Number("9007199254740993"),
			"nested": map[string]interface{}{
				"items": []interface{}{"original", json.Number("1.00")},
			},
		},
	}

	snapshot, err := SnapshotToolCall(call)
	if err != nil {
		t.Fatal(err)
	}
	call.Arguments["n"] = json.Number("2")
	nested := call.Arguments["nested"].(map[string]interface{})
	nested["items"].([]interface{})[0] = "mutated"

	if got := snapshot.Arguments["n"].(json.Number).String(); got != "9007199254740993" {
		t.Fatalf("snapshot number mutated to %q", got)
	}
	snapshotNested := snapshot.Arguments["nested"].(map[string]interface{})
	if got := snapshotNested["items"].([]interface{})[0]; got != "original" {
		t.Fatalf("snapshot nested value mutated to %#v", got)
	}
}

func TestSnapshotToolCallRejectsLossyFloat(t *testing.T) {
	_, err := SnapshotToolCall(ToolCall{Tool: "demo", Arguments: map[string]interface{}{"n": float64(1)}})
	if err == nil {
		t.Fatal("SnapshotToolCall accepted float64 input")
	}
}

func TestSnapshotResolvedPolicyDeepCopiesMapsAndSlices(t *testing.T) {
	p, err := ParsePolicy([]byte(`version: "0.1"
defaults:
  decision: deny
groups:
  readers:
    - filesystem.read
tools:
  readers:
    decision: allow
redaction:
  enabled: true
  patterns:
    - name: secret
      regex: secret
`))
	if err != nil {
		t.Fatal(err)
	}

	snapshot, err := SnapshotResolvedPolicy(p)
	if err != nil {
		t.Fatal(err)
	}
	p.Tools["readers"] = Rule{Decision: DecisionDeny}
	p.Groups["readers"][0] = "mutated.tool"
	p.Redaction.Patterns[0].Regex = "mutated"

	if got := snapshot.Tools["readers"].Decision; got != DecisionAllow {
		t.Fatalf("snapshot decision mutated to %q", got)
	}
	if got := snapshot.Groups["readers"][0]; got != "filesystem.read" {
		t.Fatalf("snapshot group mutated to %q", got)
	}
	if got := snapshot.Redaction.Patterns[0].Regex; got != "secret" {
		t.Fatalf("snapshot redaction pattern mutated to %q", got)
	}
}

func TestSnapshotResolvedPolicyRejectsUnresolvedImports(t *testing.T) {
	p, err := ParsePolicy([]byte(`version: "0.1"
defaults:
  decision: deny
`))
	if err != nil {
		t.Fatal(err)
	}
	p.Imports = []string{"child.yaml"}
	if _, err := SnapshotResolvedPolicy(p); err == nil {
		t.Fatal("SnapshotResolvedPolicy accepted unresolved imports")
	}
}
