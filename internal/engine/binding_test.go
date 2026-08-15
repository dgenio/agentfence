package engine

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/dgenio/agentfence/internal/policy"
)

func TestEvaluateBoundAddsExactActionAndPolicyDigests(t *testing.T) {
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
	call := policy.ToolCall{
		ID:   "call-1",
		Tool: "demo.tool",
		Arguments: map[string]interface{}{
			"n": json.Number("9007199254740993"),
			"x": json.Number("1.00"),
		},
	}

	result, event := eng.EvaluateBound(call)
	if result.Decision != policy.DecisionAllow {
		t.Fatalf("decision = %q, want allow (%s)", result.Decision, result.Reason)
	}
	wantAction, err := policy.ToolActionDigest(call)
	if err != nil {
		t.Fatal(err)
	}
	wantPolicy, err := policy.EffectivePolicyDigest(p)
	if err != nil {
		t.Fatal(err)
	}
	if event.ActionDigest != wantAction {
		t.Fatalf("action_digest = %q, want %q", event.ActionDigest, wantAction)
	}
	if event.PolicyDigest != wantPolicy {
		t.Fatalf("policy_digest = %q, want %q", event.PolicyDigest, wantPolicy)
	}
	if !strings.HasPrefix(event.ActionDigest, policy.ToolActionDigestAlgorithm+":sha256:") {
		t.Fatalf("unexpected action digest %q", event.ActionDigest)
	}
	if !strings.HasPrefix(event.PolicyDigest, policy.ResolvedPolicyDigestAlgorithm+":sha256:") {
		t.Fatalf("unexpected policy digest %q", event.PolicyDigest)
	}
}

func TestEvaluateBoundFailsClosedOnLossyAction(t *testing.T) {
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

	result, event := eng.EvaluateBound(policy.ToolCall{
		ID:        "call-1",
		Tool:      "demo.tool",
		Arguments: map[string]interface{}{"n": float64(9007199254740993)},
	})
	if result.Decision != policy.DecisionDeny {
		t.Fatalf("decision = %q, want deny", result.Decision)
	}
	if result.ReasonCode != policy.ReasonCodeActionBindingFailed {
		t.Fatalf("reason_code = %q, want %q", result.ReasonCode, policy.ReasonCodeActionBindingFailed)
	}
	if event.ActionDigest != "" || event.PolicyDigest != "" {
		t.Fatalf("binding failure unexpectedly recorded digests: action=%q policy=%q", event.ActionDigest, event.PolicyDigest)
	}
	if event.Arguments != nil {
		t.Fatalf("binding failure recorded ambiguous arguments: %#v", event.Arguments)
	}
}

func TestEvaluateBoundFailsClosedOnUnresolvedPolicy(t *testing.T) {
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
	p.Imports = []string{"child.yaml"}
	eng, err := New(p)
	if err != nil {
		t.Fatal(err)
	}
	call := policy.ToolCall{ID: "call-1", Tool: "demo.tool", Arguments: map[string]interface{}{}}

	result, event := eng.EvaluateBound(call)
	if result.Decision != policy.DecisionDeny {
		t.Fatalf("decision = %q, want deny", result.Decision)
	}
	if result.ReasonCode != policy.ReasonCodePolicyBindingFailed {
		t.Fatalf("reason_code = %q, want %q", result.ReasonCode, policy.ReasonCodePolicyBindingFailed)
	}
	if event.ActionDigest == "" {
		t.Fatal("policy binding failure should retain the successfully computed action digest")
	}
	if event.PolicyDigest != "" {
		t.Fatalf("policy binding failure unexpectedly recorded policy digest %q", event.PolicyDigest)
	}
}

func TestSessionEvaluateBoundPreservesDigestsAcrossTaintEscalation(t *testing.T) {
	p, err := policy.ParsePolicy([]byte(`version: "0.1"
defaults:
  decision: deny
tools:
  demo.tool:
    decision: allow
taint:
  enabled: true
  min_length: 4
`))
	if err != nil {
		t.Fatal(err)
	}
	eng, err := New(p)
	if err != nil {
		t.Fatal(err)
	}
	session := eng.NewSession()
	session.ObserveResult("source.tool", "secret-value")

	result, event := session.EvaluateBound(policy.ToolCall{
		ID:        "call-1",
		Tool:      "demo.tool",
		Arguments: map[string]interface{}{"value": "prefix secret-value suffix"},
	})
	if result.Decision != policy.DecisionAsk {
		t.Fatalf("decision = %q, want ask after taint escalation", result.Decision)
	}
	if event.ActionDigest == "" || event.PolicyDigest == "" {
		t.Fatalf("taint escalation lost binding evidence: action=%q policy=%q", event.ActionDigest, event.PolicyDigest)
	}
}
