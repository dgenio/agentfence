package approval

import (
	"encoding/json"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dgenio/agentfence/internal/policy"
)

func testBinding(t *testing.T, number string, decision policy.Decision) Binding {
	t.Helper()
	call := policy.ToolCall{
		ID:   "call-1",
		Tool: "demo.tool",
		Arguments: map[string]interface{}{
			"n": json.Number(number),
		},
	}
	actionDigest, err := policy.ToolActionDigest(call)
	if err != nil {
		t.Fatal(err)
	}
	p, err := policy.ParsePolicy([]byte("version: \"0.1\"\ndefaults:\n  decision: " + string(decision) + "\n"))
	if err != nil {
		t.Fatal(err)
	}
	policyDigest, err := policy.EffectivePolicyDigest(p)
	if err != nil {
		t.Fatal(err)
	}
	binding, err := NewBinding(actionDigest, policyDigest)
	if err != nil {
		t.Fatal(err)
	}
	return binding
}

func TestBindingDigestIsDeterministicAndBrandNeutral(t *testing.T) {
	binding := testBinding(t, "1.00", policy.DecisionDeny)
	first, err := binding.Digest()
	if err != nil {
		t.Fatal(err)
	}
	second, err := binding.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatalf("binding digest changed: %q != %q", first, second)
	}
	if !strings.HasPrefix(first, BindingDigestAlgorithm+":sha256:") {
		t.Fatalf("digest = %q, want versioned approval-binding prefix", first)
	}
	lower := strings.ToLower(first)
	if strings.Contains(lower, "agentfence") || strings.Contains(lower, "vericordon") {
		t.Fatalf("binding digest prefix must be brand-neutral: %q", first)
	}
}

func TestBindingDigestChangesWithActionOrPolicy(t *testing.T) {
	base := testBinding(t, "1", policy.DecisionDeny)
	changedAction := testBinding(t, "1.0", policy.DecisionDeny)
	changedPolicy := testBinding(t, "1", policy.DecisionAllow)

	baseDigest, err := base.Digest()
	if err != nil {
		t.Fatal(err)
	}
	actionDigest, err := changedAction.Digest()
	if err != nil {
		t.Fatal(err)
	}
	policyDigest, err := changedPolicy.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if actionDigest == baseDigest {
		t.Fatal("changed exact action retained approval binding digest")
	}
	if policyDigest == baseDigest {
		t.Fatal("changed effective policy retained approval binding digest")
	}
}

func TestNewBindingRejectsMalformedOrWrongAlgorithmDigests(t *testing.T) {
	valid := testBinding(t, "1", policy.DecisionDeny)

	badActions := []string{
		"sha256:" + strings.Repeat("a", 64),
		policy.ToolActionDigestAlgorithm + ":sha256:" + strings.Repeat("A", 64),
		policy.ToolActionDigestAlgorithm + ":sha256:abc",
	}
	for _, bad := range badActions {
		if _, err := NewBinding(bad, valid.PolicyDigest); err == nil {
			t.Fatalf("NewBinding accepted malformed action digest %q", bad)
		}
	}
	if _, err := NewBinding(valid.ActionDigest, policy.ToolActionDigestAlgorithm+":sha256:"+strings.Repeat("b", 64)); err == nil {
		t.Fatal("NewBinding accepted action algorithm for policy digest")
	}
}

func TestOneShotPermitRejectsReplaySubstitutionAndExpiry(t *testing.T) {
	binding := testBinding(t, "1", policy.DecisionDeny)
	otherAction := testBinding(t, "2", policy.DecisionDeny)
	otherPolicy := testBinding(t, "1", policy.DecisionAllow)
	issued := time.Date(2026, 8, 15, 9, 0, 0, 0, time.UTC)
	expires := issued.Add(time.Minute)

	for name, candidate := range map[string]Binding{
		"changed action": otherAction,
		"changed policy": otherPolicy,
	} {
		t.Run(name, func(t *testing.T) {
			permit, err := NewOneShotPermit(binding, issued, expires)
			if err != nil {
				t.Fatal(err)
			}
			if err := permit.Consume(candidate, issued.Add(time.Second)); err == nil {
				t.Fatal("substituted binding consumed permit")
			}
			if permit.Consumed() {
				t.Fatal("binding mismatch consumed permit")
			}
		})
	}

	permit, err := NewOneShotPermit(binding, issued, expires)
	if err != nil {
		t.Fatal(err)
	}
	if err := permit.Consume(binding, expires); err == nil {
		t.Fatal("permit was valid at its expiry boundary")
	}
	if permit.Consumed() {
		t.Fatal("expired attempt consumed permit")
	}
	if err := permit.Consume(binding, issued.Add(30*time.Second)); err != nil {
		t.Fatalf("first valid consume failed: %v", err)
	}
	if err := permit.Consume(binding, issued.Add(31*time.Second)); err == nil {
		t.Fatal("replayed permit succeeded")
	}
}

func TestOneShotPermitRequiresExplicitFiniteInterval(t *testing.T) {
	binding := testBinding(t, "1", policy.DecisionDeny)
	now := time.Date(2026, 8, 15, 9, 0, 0, 0, time.UTC)

	if _, err := NewOneShotPermit(binding, time.Time{}, now.Add(time.Minute)); err == nil {
		t.Fatal("permit accepted missing issued_at")
	}
	if _, err := NewOneShotPermit(binding, now, time.Time{}); err == nil {
		t.Fatal("permit accepted missing expires_at")
	}
	if _, err := NewOneShotPermit(binding, now, now); err == nil {
		t.Fatal("permit accepted zero validity interval")
	}
	permit, err := NewOneShotPermit(binding, now, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if err := permit.Consume(binding, now.Add(-time.Second)); err == nil {
		t.Fatal("permit accepted use before issuance")
	}
}

func TestOneShotPermitConcurrentConsumeAllowsExactlyOne(t *testing.T) {
	binding := testBinding(t, "1", policy.DecisionDeny)
	issued := time.Date(2026, 8, 15, 9, 0, 0, 0, time.UTC)
	permit, err := NewOneShotPermit(binding, issued, issued.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}

	const consumers = 16
	var successes atomic.Int32
	var wg sync.WaitGroup
	wg.Add(consumers)
	for i := 0; i < consumers; i++ {
		go func() {
			defer wg.Done()
			if err := permit.Consume(binding, issued.Add(time.Second)); err == nil {
				successes.Add(1)
			}
		}()
	}
	wg.Wait()
	if got := successes.Load(); got != 1 {
		t.Fatalf("successful consumes = %d, want exactly 1", got)
	}
}
