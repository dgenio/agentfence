package audit

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/dgenio/agentfence/internal/policy"
)

func TestWriterPreservesDecisionBindingDigests(t *testing.T) {
	var out bytes.Buffer
	writer := NewWriterOptions(&out, Options{SessionID: "binding-test"})

	event := Event{
		Timestamp:    "2026-08-15T00:00:00Z",
		CallID:       "call-1",
		Tool:         "demo.tool",
		Decision:     policy.DecisionAllow,
		Reason:       "test",
		ReasonCode:   policy.ReasonCodeRuleMatch,
		ActionDigest: "tool-action-json-v1:sha256:" + strings.Repeat("a", 64),
		PolicyDigest: "resolved-policy-json-v1:sha256:" + strings.Repeat("b", 64),
	}
	if err := writer.Write(event); err != nil {
		t.Fatalf("Write() error = %v", err)
	}

	var got Event
	if err := json.Unmarshal(bytes.TrimSpace(out.Bytes()), &got); err != nil {
		t.Fatalf("decode event: %v", err)
	}
	if got.SchemaVersion != "5" {
		t.Fatalf("schema_version = %q, want 5", got.SchemaVersion)
	}
	if got.ActionDigest != event.ActionDigest {
		t.Fatalf("action_digest = %q, want %q", got.ActionDigest, event.ActionDigest)
	}
	if got.PolicyDigest != event.PolicyDigest {
		t.Fatalf("policy_digest = %q, want %q", got.PolicyDigest, event.PolicyDigest)
	}
}

func TestDecisionBindingDigestsAffectTamperEvidence(t *testing.T) {
	base := Event{
		SchemaVersion: "5",
		SessionID:     "binding-test",
		Sequence:      1,
		Timestamp:     "2026-08-15T00:00:00Z",
		CallID:        "call-1",
		Tool:          "demo.tool",
		Decision:      policy.DecisionAllow,
		Reason:        "test",
		ReasonCode:    policy.ReasonCodeRuleMatch,
		ActionDigest:  "tool-action-json-v1:sha256:" + strings.Repeat("a", 64),
		PolicyDigest:  "resolved-policy-json-v1:sha256:" + strings.Repeat("b", 64),
	}

	baseHash, err := hashEvent(base)
	if err != nil {
		t.Fatalf("hashEvent(base) error = %v", err)
	}

	changedAction := base
	changedAction.ActionDigest = "tool-action-json-v1:sha256:" + strings.Repeat("c", 64)
	changedActionHash, err := hashEvent(changedAction)
	if err != nil {
		t.Fatalf("hashEvent(changedAction) error = %v", err)
	}
	if changedActionHash == baseHash {
		t.Fatal("changing action_digest did not change event hash")
	}

	changedPolicy := base
	changedPolicy.PolicyDigest = "resolved-policy-json-v1:sha256:" + strings.Repeat("d", 64)
	changedPolicyHash, err := hashEvent(changedPolicy)
	if err != nil {
		t.Fatalf("hashEvent(changedPolicy) error = %v", err)
	}
	if changedPolicyHash == baseHash {
		t.Fatal("changing policy_digest did not change event hash")
	}
}
