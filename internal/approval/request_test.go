package approval

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/dgenio/agentfence/internal/policy"
	"github.com/dgenio/agentfence/internal/redact"
)

func approvalRequestFixture(t *testing.T, call policy.ToolCall, redaction policy.RedactionConfig) BoundRequest {
	t.Helper()
	actionDigest, err := policy.ToolActionDigest(call)
	if err != nil {
		t.Fatal(err)
	}
	p, err := policy.ParsePolicy([]byte(`version: "0.1"
defaults:
  decision: deny
`))
	if err != nil {
		t.Fatal(err)
	}
	policyDigest, err := policy.EffectivePolicyDigest(p)
	if err != nil {
		t.Fatal(err)
	}
	r, err := redact.New(redaction)
	if err != nil {
		t.Fatal(err)
	}
	request, err := NewBoundRequest(call, actionDigest, policyDigest, r)
	if err != nil {
		t.Fatal(err)
	}
	return request
}

func TestBoundRequestRedactsConfiguredSecretsEvenWhenAuditRedactionDisabled(t *testing.T) {
	secret := "token=super-secret-value"
	call := policy.ToolCall{
		ID:   "call-1",
		Tool: "filesystem.write",
		Arguments: map[string]interface{}{
			"path":    ".env",
			"content": secret,
		},
	}
	request := approvalRequestFixture(t, call, policy.RedactionConfig{
		Enabled: false,
		Patterns: []policy.RedactionPattern{{
			Name:  "secret_assignment",
			Regex: `token=[^\s]+`,
		}},
	})

	if strings.Contains(request.ArgumentsDisplay(), secret) || strings.Contains(request.Prompt(), secret) {
		t.Fatal("bound approval request leaked raw configured secret")
	}
	if !strings.Contains(request.ArgumentsDisplay(), "[REDACTED:secret_assignment]") {
		t.Fatalf("arguments display = %q, want configured redaction marker", request.ArgumentsDisplay())
	}
}

func TestBoundRequestDisplayIsDeterministicAndBounded(t *testing.T) {
	redaction := policy.RedactionConfig{}
	callA := policy.ToolCall{
		ID:   "a",
		Tool: "demo.tool",
		Arguments: map[string]interface{}{
			"z": json.Number("1.00"),
			"a": "value",
		},
	}
	callB := policy.ToolCall{
		ID:   "b",
		Tool: "demo.tool",
		Arguments: map[string]interface{}{
			"a": "value",
			"z": json.Number("1.00"),
		},
	}
	requestA := approvalRequestFixture(t, callA, redaction)
	requestB := approvalRequestFixture(t, callB, redaction)
	if requestA.ArgumentsDisplay() != requestB.ArgumentsDisplay() {
		t.Fatalf("map order changed display: %q != %q", requestA.ArgumentsDisplay(), requestB.ArgumentsDisplay())
	}
	if requestA.ActionDigest() != requestB.ActionDigest() {
		t.Fatalf("correlation ID changed action digest: %q != %q", requestA.ActionDigest(), requestB.ActionDigest())
	}

	large := policy.ToolCall{
		ID:        "large",
		Tool:      "demo.tool",
		Arguments: map[string]interface{}{"content": strings.Repeat("x", MaxArgumentsDisplayBytes*2)},
	}
	largeRequest := approvalRequestFixture(t, large, redaction)
	if len(largeRequest.ArgumentsDisplay()) > MaxArgumentsDisplayBytes {
		t.Fatalf("bounded display length = %d, exceeds %d", len(largeRequest.ArgumentsDisplay()), MaxArgumentsDisplayBytes)
	}
	if !strings.Contains(largeRequest.ArgumentsDisplay(), `"omitted":true`) {
		t.Fatalf("large display = %q, want omission summary", largeRequest.ArgumentsDisplay())
	}
	if strings.Contains(largeRequest.ArgumentsDisplay(), strings.Repeat("x", 64)) {
		t.Fatal("large display included raw argument content")
	}
}

func TestBoundRequestRejectsDigestSubstitutionAndLossyCalls(t *testing.T) {
	call := policy.ToolCall{ID: "call-1", Tool: "demo.tool", Arguments: map[string]interface{}{"n": json.Number("1")}}
	actionDigest, err := policy.ToolActionDigest(call)
	if err != nil {
		t.Fatal(err)
	}
	otherDigest, err := policy.ToolActionDigest(policy.ToolCall{ID: "other", Tool: "demo.tool", Arguments: map[string]interface{}{"n": json.Number("2")}})
	if err != nil {
		t.Fatal(err)
	}
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

	if _, err := NewBoundRequest(call, otherDigest, policyDigest, r); err == nil {
		t.Fatal("NewBoundRequest accepted action digest from another action")
	}
	if _, err := NewBoundRequest(call, actionDigest, policy.ToolActionDigestAlgorithm+":sha256:"+strings.Repeat("a", 64), r); err == nil {
		t.Fatal("NewBoundRequest accepted wrong algorithm for policy digest")
	}
	lossy := policy.ToolCall{ID: "lossy", Tool: "demo.tool", Arguments: map[string]interface{}{"n": float64(1)}}
	if _, err := NewBoundRequest(lossy, actionDigest, policyDigest, r); err == nil {
		t.Fatal("NewBoundRequest accepted lossy float action")
	}
	if _, err := NewBoundRequest(call, actionDigest, policyDigest, nil); err == nil {
		t.Fatal("NewBoundRequest accepted nil redactor")
	}
}

func TestBoundRequestKeepsImmutableExactSnapshot(t *testing.T) {
	call := policy.ToolCall{
		ID:   "call-1",
		Tool: "demo.tool",
		Arguments: map[string]interface{}{
			"mode":   "read",
			"nested": map[string]interface{}{"n": json.Number("1.00")},
		},
	}
	request := approvalRequestFixture(t, call, policy.RedactionConfig{})
	wantDigest := request.ActionDigest()
	wantDisplay := request.ArgumentsDisplay()

	call.Arguments["mode"] = "write"
	call.Arguments["nested"].(map[string]interface{})["n"] = json.Number("2")

	snapshot, err := request.CallSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Arguments["mode"] != "read" {
		t.Fatalf("request snapshot mutated to %#v", snapshot.Arguments["mode"])
	}
	if request.ActionDigest() != wantDigest || request.ArgumentsDisplay() != wantDisplay {
		t.Fatal("caller mutation changed immutable approval request evidence")
	}

	snapshot.Arguments["mode"] = "mutated-copy"
	again, err := request.CallSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	if again.Arguments["mode"] != "read" {
		t.Fatal("mutation of returned snapshot changed internal approval request")
	}
}

func TestBoundRequestBindingMatchesActionAndPolicyEvidence(t *testing.T) {
	request := approvalRequestFixture(t, policy.ToolCall{
		ID:        "call-1",
		Tool:      "demo.tool",
		Arguments: map[string]interface{}{"n": json.Number("1")},
	}, policy.RedactionConfig{})
	binding, err := NewBinding(request.ActionDigest(), request.PolicyDigest())
	if err != nil {
		t.Fatal(err)
	}
	want, err := binding.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if request.BindingDigest() != want {
		t.Fatalf("binding digest = %q, want %q", request.BindingDigest(), want)
	}
	for _, token := range []string{request.ActionDigest(), request.PolicyDigest(), request.BindingDigest()} {
		if !strings.Contains(request.Prompt(), token) {
			t.Fatalf("prompt omitted binding evidence %q", token)
		}
	}
}
