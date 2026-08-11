package engine

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/dgenio/agentfence/internal/policy"
)

func TestJSONNumberArgumentMatchesExactlyAndAuditsLosslessly(t *testing.T) {
	p := policy.Policy{
		Defaults: policy.Defaults{Decision: policy.DecisionDeny},
		Tools: map[string]policy.Rule{
			"demo": {
				Decision: policy.DecisionAllow,
				Constraints: policy.Constraints{Args: map[string]policy.ArgValueConstraint{
					"amount": {Allow: []string{"9007199254740993"}},
				}},
			},
		},
		Audit: policy.AuditConfig{Format: "jsonl", IncludeRedactedArguments: true},
	}

	eng, err := New(p)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	call, err := policy.ParseToolCall([]byte(`{"id":"c1","tool":"demo","arguments":{"amount":9007199254740993}}`))
	if err != nil {
		t.Fatalf("ParseToolCall() error = %v", err)
	}

	result, event := eng.Evaluate(call)
	if result.Decision != policy.DecisionAllow {
		t.Fatalf("Evaluate() decision = %q (%s), want allow", result.Decision, result.Reason)
	}

	encoded, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("json.Marshal(event) error = %v", err)
	}
	if !strings.Contains(string(encoded), `"amount":9007199254740993`) {
		t.Fatalf("audit event rounded or quoted large integer: %s", encoded)
	}
}

func TestJSONNumberAndStringRemainDistinctForArgumentPolicy(t *testing.T) {
	p := policy.Policy{
		Defaults: policy.Defaults{Decision: policy.DecisionDeny},
		Tools: map[string]policy.Rule{
			"demo": {
				Decision: policy.DecisionAllow,
				Constraints: policy.Constraints{Args: map[string]policy.ArgValueConstraint{
					"amount": {Allow: []string{"9007199254740993"}},
				}},
			},
		},
	}
	eng, err := New(p)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	numberCall, err := policy.ParseToolCall([]byte(`{"id":"n","tool":"demo","arguments":{"amount":9007199254740993}}`))
	if err != nil {
		t.Fatal(err)
	}
	stringCall, err := policy.ParseToolCall([]byte(`{"id":"s","tool":"demo","arguments":{"amount":"9007199254740993"}}`))
	if err != nil {
		t.Fatal(err)
	}

	if _, ok := numberCall.Arguments["amount"].(json.Number); !ok {
		t.Fatalf("numeric amount type = %T, want json.Number", numberCall.Arguments["amount"])
	}
	if _, ok := stringCall.Arguments["amount"].(string); !ok {
		t.Fatalf("string amount type = %T, want string", stringCall.Arguments["amount"])
	}

	// The current generic argument constraint intentionally compares scalar
	// values by their text form, so both can match the same glob. This test pins
	// the more fundamental invariant required by #222: the parsed semantic types
	// remain distinct for future action canonicalization even when an existing
	// rule's string-oriented matching treats them equivalently.
}
