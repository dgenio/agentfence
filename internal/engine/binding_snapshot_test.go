package engine

import (
	"encoding/json"
	"testing"

	"github.com/dgenio/agentfence/internal/policy"
)

func TestEvaluateBoundSnapshotUsesFingerprintExactCall(t *testing.T) {
	p, err := policy.ParsePolicy([]byte(`version: "0.1"
defaults:
  decision: deny
tools:
  demo.tool:
    decision: allow
    constraints:
      args:
        mode:
          allow:
            - read
`))
	if err != nil {
		t.Fatal(err)
	}
	eng, err := New(p)
	if err != nil {
		t.Fatal(err)
	}
	original := policy.ToolCall{
		ID:   "call-1",
		Tool: "demo.tool",
		Arguments: map[string]interface{}{
			"mode": "read",
			"nested": map[string]interface{}{
				"n": json.Number("1.00"),
			},
		},
	}
	snapshot, err := policy.SnapshotToolCall(original)
	if err != nil {
		t.Fatal(err)
	}
	wantDigest, err := policy.ToolActionDigest(snapshot)
	if err != nil {
		t.Fatal(err)
	}

	// Mutate the caller-owned graph after the exact snapshot was captured. The
	// bound evaluator must keep authorizing and evidencing the snapshot, not the
	// later mutation.
	original.Arguments["mode"] = "write"
	original.Arguments["nested"].(map[string]interface{})["n"] = json.Number("2")

	result, event := eng.evaluateBoundSnapshot(snapshot)
	if result.Decision != policy.DecisionAllow {
		t.Fatalf("snapshot decision = %q, want allow (%s)", result.Decision, result.Reason)
	}
	if event.ActionDigest != wantDigest {
		t.Fatalf("action_digest = %q, want fingerprint of snapshot %q", event.ActionDigest, wantDigest)
	}
}

func TestEvaluateBoundSnapshotUsesFingerprintExactPolicy(t *testing.T) {
	p, err := policy.ParsePolicy([]byte(`version: "0.1"
defaults:
  decision: deny
tools:
  demo.tool:
    decision: allow
`))
	if err != nil {
		t.Fatal(err)
	}
	eng, err := New(p)
	if err != nil {
		t.Fatal(err)
	}
	call, err := policy.SnapshotToolCall(policy.ToolCall{ID: "call-1", Tool: "demo.tool", Arguments: map[string]interface{}{}})
	if err != nil {
		t.Fatal(err)
	}

	// Mutating the caller's original policy after Engine construction currently
	// mutates eng.policy too because Policy contains maps. EvaluateBound must take
	// one deep policy snapshot and use that same snapshot for digest + decision.
	p.Tools["demo.tool"] = policy.Rule{Decision: policy.DecisionDeny}

	result, event := eng.evaluateBoundSnapshot(call)
	if result.Decision != policy.DecisionDeny {
		t.Fatalf("decision = %q, want deny from captured effective policy", result.Decision)
	}
	wantPolicy, err := policy.EffectivePolicyDigest(eng.policy)
	if err != nil {
		t.Fatal(err)
	}
	if event.PolicyDigest != wantPolicy {
		t.Fatalf("policy_digest = %q, want digest of evaluated policy %q", event.PolicyDigest, wantPolicy)
	}
}
