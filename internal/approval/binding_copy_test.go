package approval

import (
	"testing"
	"time"

	"github.com/dgenio/agentfence/internal/policy"
)

func TestOneShotPermitCopyCannotReplay(t *testing.T) {
	binding := testBinding(t, "1", policy.DecisionDeny)
	issued := time.Date(2026, 8, 15, 9, 0, 0, 0, time.UTC)
	permit, err := NewOneShotPermit(binding, issued, issued.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}

	copied := *permit
	if err := permit.Consume(binding, issued.Add(time.Second)); err != nil {
		t.Fatalf("original consume failed: %v", err)
	}
	if err := copied.Consume(binding, issued.Add(2*time.Second)); err == nil {
		t.Fatal("copied permit replay succeeded")
	}
	if !copied.Consumed() {
		t.Fatal("copied permit did not share consumed state")
	}
}

func TestOneShotPermitMetadataAccessorsAreStable(t *testing.T) {
	binding := testBinding(t, "1", policy.DecisionDeny)
	issued := time.Date(2026, 8, 15, 9, 0, 0, 0, time.UTC)
	expires := issued.Add(time.Minute)
	permit, err := NewOneShotPermit(binding, issued, expires)
	if err != nil {
		t.Fatal(err)
	}
	wantDigest, err := binding.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if permit.BindingDigest() != wantDigest {
		t.Fatalf("BindingDigest() = %q, want %q", permit.BindingDigest(), wantDigest)
	}
	if !permit.IssuedAt().Equal(issued) {
		t.Fatalf("IssuedAt() = %v, want %v", permit.IssuedAt(), issued)
	}
	if !permit.ExpiresAt().Equal(expires) {
		t.Fatalf("ExpiresAt() = %v, want %v", permit.ExpiresAt(), expires)
	}
}
