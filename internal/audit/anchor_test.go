package audit

import (
	"bytes"
	"errors"
	"testing"

	"github.com/dgenio/agentfence/internal/policy"
)

// chainedLog writes n chained events and returns the raw bytes.
func chainedLog(t *testing.T, n int) []byte {
	t.Helper()
	buf := &bytes.Buffer{}
	w := NewWriterOptions(buf, Options{TamperEvident: true, SessionID: "sess-1"})
	for i := 0; i < n; i++ {
		if err := w.Write(Event{CallID: "c", Tool: "t", Decision: policy.DecisionAllow}); err != nil {
			t.Fatalf("Write: %v", err)
		}
	}
	return buf.Bytes()
}

func TestComputeAndVerifyAnchor(t *testing.T) {
	log := chainedLog(t, 3)
	anchor, err := ComputeAnchor(bytes.NewReader(log), nil)
	if err != nil {
		t.Fatalf("ComputeAnchor: %v", err)
	}
	if anchor.EventCount != 3 || anchor.LastSeq != 3 || anchor.LastHash == "" {
		t.Fatalf("unexpected anchor: %+v", anchor)
	}
	if anchor.SessionID != "sess-1" {
		t.Fatalf("session_id = %q, want sess-1", anchor.SessionID)
	}
	if err := VerifyAgainstAnchor(bytes.NewReader(log), anchor); err != nil {
		t.Fatalf("VerifyAgainstAnchor: %v", err)
	}
}

func TestVerifyAnchorAcceptsGrownLog(t *testing.T) {
	log := chainedLog(t, 2)
	anchor, err := ComputeAnchor(bytes.NewReader(log), nil)
	if err != nil {
		t.Fatalf("ComputeAnchor: %v", err)
	}
	// Continue the chain and append two more events; the anchored event is
	// still present, so verification must still pass.
	buf := bytes.NewBuffer(append([]byte{}, log...))
	lastHash, err := LastChainHash(bytes.NewReader(log))
	if err != nil {
		t.Fatalf("LastChainHash: %v", err)
	}
	w := NewWriterOptions(buf, Options{TamperEvident: true, SessionID: "sess-1", InitialPrevHash: lastHash})
	// advance seq past the anchored events so the appended events look realistic
	w.seq = 2
	_ = w.Write(Event{CallID: "c3", Tool: "t", Decision: policy.DecisionDeny})
	_ = w.Write(Event{CallID: "c4", Tool: "t", Decision: policy.DecisionDeny})

	if err := VerifyAgainstAnchor(bytes.NewReader(buf.Bytes()), anchor); err != nil {
		t.Fatalf("VerifyAgainstAnchor on grown log: %v", err)
	}
}

func TestVerifyAnchorDetectsTruncation(t *testing.T) {
	log := chainedLog(t, 4)
	anchor, err := ComputeAnchor(bytes.NewReader(log), nil)
	if err != nil {
		t.Fatalf("ComputeAnchor: %v", err)
	}
	// Truncate to the first two events: the anchored event 4 is gone.
	lines := bytes.SplitAfter(log, []byte("\n"))
	truncated := bytes.Join(lines[:2], nil)
	err = VerifyAgainstAnchor(bytes.NewReader(truncated), anchor)
	if !errors.Is(err, ErrAnchorTruncated) {
		t.Fatalf("expected ErrAnchorTruncated, got %v", err)
	}
}

func TestComputeAnchorRejectsUnchainedLog(t *testing.T) {
	buf := &bytes.Buffer{}
	w := NewWriter(buf) // not tamper-evident
	_ = w.Write(Event{CallID: "c1", Tool: "t", Decision: policy.DecisionAllow})
	_, err := ComputeAnchor(bytes.NewReader(buf.Bytes()), nil)
	if !errors.Is(err, ErrNoChain) {
		t.Fatalf("expected ErrNoChain, got %v", err)
	}
}

func TestSignedAnchorRoundTrip(t *testing.T) {
	signer := newTestSigner(t)
	log := chainedLog(t, 2)
	anchor, err := ComputeAnchor(bytes.NewReader(log), signer)
	if err != nil {
		t.Fatalf("ComputeAnchor: %v", err)
	}
	if anchor.Signature == "" {
		t.Fatal("expected signed anchor")
	}
	if err := VerifyAnchorSignature(anchor, signer.Public()); err != nil {
		t.Fatalf("VerifyAnchorSignature: %v", err)
	}
	// Mutating the anchor invalidates the signature.
	anchor.EventCount = 99
	if err := VerifyAnchorSignature(anchor, signer.Public()); err == nil {
		t.Fatal("expected signature mismatch after mutation")
	}
}
