package approval

import (
	"encoding/json"
	"testing"

	"github.com/dgenio/agentfence/internal/policy"
	"github.com/dgenio/agentfence/internal/redact"
)

func TestBoundRequestRequiresCallIDAndTool(t *testing.T) {
	p, err := policy.ParsePolicy([]byte("version: \"0.1\"\n"))
	if err != nil {
		t.Fatal(err)
	}
	policyDigest, err := policy.EffectivePolicyDigest(p)
	if err != nil {
		t.Fatal(err)
	}
	r, err := redact.New(policy.RedactionConfig{})
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name string
		call policy.ToolCall
	}{
		{name: "missing call id", call: policy.ToolCall{Tool: "demo.tool", Arguments: map[string]interface{}{"n": json.Number("1")}}},
		{name: "missing tool", call: policy.ToolCall{ID: "call-1", Arguments: map[string]interface{}{"n": json.Number("1")}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			actionDigest, err := policy.ToolActionDigest(tc.call)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := NewBoundRequest(tc.call, actionDigest, policyDigest, r); err == nil {
				t.Fatal("NewBoundRequest accepted incomplete call identity")
			}
		})
	}
}
