package engine

import (
	"encoding/json"
	"testing"

	"github.com/dgenio/agentfence/internal/policy"
)

func TestJSONNumberArgumentConstraintsRemainDeterministic(t *testing.T) {
	p := policy.Policy{
		Defaults: policy.Defaults{Decision: policy.DecisionDeny},
		Tools: map[string]policy.Rule{
			"example.run": {
				Decision: policy.DecisionAllow,
				Constraints: policy.Constraints{
					Args: map[string]policy.ArgValueConstraint{
						"id": {Allow: []string{"9007199254740993"}},
					},
				},
			},
		},
	}

	eng, err := New(p)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	allowed, _ := eng.Evaluate(policy.ToolCall{
		ID: "c1", Tool: "example.run",
		Arguments: map[string]interface{}{"id": json.Number("9007199254740993")},
	})
	if allowed.Decision != policy.DecisionAllow {
		t.Fatalf("exact json.Number decision = %s, want allow (reason: %s)", allowed.Decision, allowed.Reason)
	}

	denied, _ := eng.Evaluate(policy.ToolCall{
		ID: "c2", Tool: "example.run",
		Arguments: map[string]interface{}{"id": json.Number("9007199254740992")},
	})
	if denied.Decision != policy.DecisionDeny {
		t.Fatalf("different json.Number decision = %s, want deny", denied.Decision)
	}
}
