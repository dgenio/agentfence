package audit

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/dgenio/agentfence/internal/policy"
)

// buildChainedLog writes n events through a tamper-evident writer and returns
// the serialised log bytes plus the writer's session id.
func buildChainedLog(t *testing.T, n int) ([]byte, string) {
	t.Helper()
	buf := &bytes.Buffer{}
	w := NewWriterOptions(buf, Options{TamperEvident: true, SessionID: "test-session"})
	for i := 0; i < n; i++ {
		if err := w.Write(Event{
			Timestamp: "2026-01-01T00:00:00Z",
			CallID:    "c",
			Tool:      "filesystem.read",
			Decision:  policy.DecisionAllow,
			Reason:    "allowed",
		}); err != nil {
			t.Fatalf("Write() error = %v", err)
		}
	}
	return buf.Bytes(), w.SessionID()
}

func TestVerifyChainValid(t *testing.T) {
	log, _ := buildChainedLog(t, 5)
	n, err := VerifyChain(bytes.NewReader(log))
	if err != nil {
		t.Fatalf("VerifyChain() error = %v", err)
	}
	if n != 5 {
		t.Errorf("verified count = %d, want 5", n)
	}
}

func TestVerifyChainEmpty(t *testing.T) {
	n, err := VerifyChain(strings.NewReader(""))
	if n != 0 {
		t.Errorf("verified count = %d, want 0", n)
	}
	if !errors.Is(err, ErrNoChain) {
		t.Errorf("err = %v, want ErrNoChain", err)
	}
}

func TestVerifyChainNonChainedLog(t *testing.T) {
	buf := &bytes.Buffer{}
	w := NewWriter(buf) // not chained
	for i := 0; i < 3; i++ {
		if err := w.Write(Event{CallID: "c", Tool: "t", Decision: policy.DecisionAllow}); err != nil {
			t.Fatalf("Write() error = %v", err)
		}
	}
	n, err := VerifyChain(buf)
	if !errors.Is(err, ErrNoChain) {
		t.Fatalf("err = %v, want ErrNoChain", err)
	}
	if n != 3 {
		t.Errorf("count = %d, want 3", n)
	}
}

func TestVerifyChainDetectsModifiedEvent(t *testing.T) {
	log, _ := buildChainedLog(t, 5)
	lines := bytes.Split(bytes.TrimRight(log, "\n"), []byte("\n"))
	if len(lines) != 5 {
		t.Fatalf("expected 5 lines, got %d", len(lines))
	}

	// Tamper with event 3 (index 2): flip the reason value but keep its hash.
	var e Event
	if err := json.Unmarshal(lines[2], &e); err != nil {
		t.Fatalf("unmarshal mid-event: %v", err)
	}
	e.Reason = "TAMPERED" // hash is untouched -> recomputed will differ
	tampered, err := json.Marshal(e)
	if err != nil {
		t.Fatalf("remarshal: %v", err)
	}
	lines[2] = tampered

	rebuilt := bytes.Join(lines, []byte("\n"))
	rebuilt = append(rebuilt, '\n')

	n, err := VerifyChain(bytes.NewReader(rebuilt))
	if err == nil {
		t.Fatalf("expected VerifyChain to fail, got nil; n=%d", n)
	}
	var ve *VerifyError
	if !errors.As(err, &ve) {
		t.Fatalf("err = %v (%T), want *VerifyError", err, err)
	}
	if ve.EventNumber != 3 {
		t.Errorf("VerifyError.EventNumber = %d, want 3", ve.EventNumber)
	}
}

func TestVerifyChainDetectsDeletedEvent(t *testing.T) {
	log, _ := buildChainedLog(t, 5)
	lines := bytes.Split(bytes.TrimRight(log, "\n"), []byte("\n"))
	// Drop event 3 (index 2). Event 4's prev_hash will no longer match.
	lines = append(lines[:2], lines[3:]...)
	rebuilt := bytes.Join(lines, []byte("\n"))
	rebuilt = append(rebuilt, '\n')

	_, err := VerifyChain(bytes.NewReader(rebuilt))
	if err == nil {
		t.Fatal("expected VerifyChain to detect deletion")
	}
	var ve *VerifyError
	if !errors.As(err, &ve) {
		t.Fatalf("err = %v, want *VerifyError", err)
	}
	if ve.EventNumber != 3 {
		t.Errorf("VerifyError.EventNumber = %d, want 3 (the third event in the shortened log)", ve.EventNumber)
	}
}

func TestVerifyChainDetectsMalformedJSON(t *testing.T) {
	log, _ := buildChainedLog(t, 2)
	bad := append(log, []byte("not json\n")...)
	_, err := VerifyChain(bytes.NewReader(bad))
	if err == nil {
		t.Fatal("expected VerifyChain to fail on malformed JSON")
	}
	var ve *VerifyError
	if !errors.As(err, &ve) {
		t.Fatalf("err = %v, want *VerifyError", err)
	}
	if ve.EventNumber != 3 {
		t.Errorf("VerifyError.EventNumber = %d, want 3", ve.EventNumber)
	}
}

func TestVerifyChainSkipsBlankLines(t *testing.T) {
	log, _ := buildChainedLog(t, 3)
	withBlanks := bytes.NewBuffer(nil)
	withBlanks.WriteString("\n")
	withBlanks.Write(log)
	withBlanks.WriteString("\n")
	n, err := VerifyChain(withBlanks)
	if err != nil {
		t.Fatalf("VerifyChain() unexpected error = %v", err)
	}
	// EventNumber count includes blank lines because we count input lines, but
	// blanks should not break verification. We just assert no error and n >= 3.
	if n < 3 {
		t.Errorf("verified count = %d, want >= 3", n)
	}
}
