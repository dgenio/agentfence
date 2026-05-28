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

func TestLastChainHashReturnsTailHash(t *testing.T) {
	log, _ := buildChainedLog(t, 3)
	lines := bytes.Split(bytes.TrimRight(log, "\n"), []byte("\n"))
	var last Event
	if err := json.Unmarshal(lines[len(lines)-1], &last); err != nil {
		t.Fatalf("unmarshal last event: %v", err)
	}

	got, err := LastChainHash(bytes.NewReader(log))
	if err != nil {
		t.Fatalf("LastChainHash() error = %v", err)
	}
	if got != last.Hash {
		t.Fatalf("LastChainHash() = %q, want %q", got, last.Hash)
	}
}

func TestLastChainHashReturnsEmptyForUnchainedLog(t *testing.T) {
	buf := &bytes.Buffer{}
	w := NewWriter(buf)
	if err := w.Write(Event{CallID: "c", Tool: "t", Decision: policy.DecisionAllow}); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	got, err := LastChainHash(buf)
	if err != nil {
		t.Fatalf("LastChainHash() error = %v", err)
	}
	if got != "" {
		t.Fatalf("LastChainHash() = %q, want empty", got)
	}
}

func TestVerifyChainEmpty(t *testing.T) {
	// Empty input is not a chain-absent case; nothing to verify and nothing
	// to complain about.
	n, err := VerifyChain(strings.NewReader(""))
	if err != nil {
		t.Errorf("VerifyChain(\"\") err = %v, want nil", err)
	}
	if n != 0 {
		t.Errorf("verified count = %d, want 0", n)
	}
}

func TestVerifyChainBlankOnlyInput(t *testing.T) {
	// A file containing only blank lines is equivalent to empty input.
	n, err := VerifyChain(strings.NewReader("\n\n   \n\n"))
	if err != nil {
		t.Errorf("VerifyChain(blanks) err = %v, want nil", err)
	}
	if n != 0 {
		t.Errorf("verified count = %d, want 0", n)
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

func TestVerifyChainPartialChain(t *testing.T) {
	// Build a mixed log: 2 unchained events, then 3 chained events appended
	// to the same buffer. This is the exact scenario openAuditOutput
	// produces when --tamper-evident is enabled on a pre-existing
	// unchained log: the suffix is integrity-protected, the prefix is not.
	buf := &bytes.Buffer{}
	plain := NewWriter(buf)
	for i := 0; i < 2; i++ {
		if err := plain.Write(Event{CallID: "u", Tool: "t", Decision: policy.DecisionAllow}); err != nil {
			t.Fatalf("plain Write() = %v", err)
		}
	}
	chained := NewWriterOptions(buf, Options{TamperEvident: true, SessionID: "mixed"})
	for i := 0; i < 3; i++ {
		if err := chained.Write(Event{
			Timestamp: "2026-01-01T00:00:00Z",
			CallID:    "c", Tool: "t", Decision: policy.DecisionAllow,
		}); err != nil {
			t.Fatalf("chained Write() = %v", err)
		}
	}

	n, err := VerifyChain(bytes.NewReader(buf.Bytes()))
	if !errors.Is(err, ErrPartialChain) {
		t.Fatalf("err = %v, want ErrPartialChain", err)
	}
	if n != 5 {
		t.Errorf("count = %d, want 5", n)
	}
	var pe *PartialChainError
	if !errors.As(err, &pe) {
		t.Fatalf("err = %v (%T), want *PartialChainError", err, err)
	}
	if pe.Total != 5 || pe.ChainStartEvent != 3 {
		t.Errorf("PartialChainError = {Total:%d ChainStartEvent:%d}, want {Total:5 ChainStartEvent:3}", pe.Total, pe.ChainStartEvent)
	}
}

func TestLastChainStateClassifiesLogs(t *testing.T) {
	// Empty log.
	if hash, n, start, err := LastChainState(strings.NewReader("")); err != nil || hash != "" || n != 0 || start != 0 {
		t.Errorf("empty: got (%q,%d,%d,%v), want (\"\",0,0,nil)", hash, n, start, err)
	}

	// Fully chained log.
	chained, _ := buildChainedLog(t, 3)
	if hash, n, start, err := LastChainState(bytes.NewReader(chained)); err != nil || hash == "" || n != 3 || start != 1 {
		t.Errorf("chained: got (%q,%d,%d,%v), want (non-empty,3,1,nil)", hash, n, start, err)
	}

	// Fully unchained log.
	plainBuf := &bytes.Buffer{}
	plain := NewWriter(plainBuf)
	for i := 0; i < 2; i++ {
		if err := plain.Write(Event{CallID: "u", Tool: "t", Decision: policy.DecisionAllow}); err != nil {
			t.Fatalf("plain Write() = %v", err)
		}
	}
	if hash, n, start, err := LastChainState(plainBuf); err != nil || hash != "" || n != 2 || start != 0 {
		t.Errorf("unchained: got (%q,%d,%d,%v), want (\"\",2,0,nil)", hash, n, start, err)
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
	withBlanks.WriteString("\n\n")
	withBlanks.Write(log)
	withBlanks.WriteString("\n  \n")
	n, err := VerifyChain(withBlanks)
	if err != nil {
		t.Fatalf("VerifyChain() unexpected error = %v", err)
	}
	// Blank/whitespace-only lines must not advance the event counter.
	if n != 3 {
		t.Errorf("verified count = %d, want 3 (blank lines should not count)", n)
	}
}

func TestVerifyChainHandlesLargeEvents(t *testing.T) {
	// Audit events with large argument payloads can easily exceed bufio.Scanner's
	// default token limit (#48 review feedback). Build a single event whose
	// argument payload is ~2 MiB and confirm verification still completes.
	buf := &bytes.Buffer{}
	w := NewWriterOptions(buf, Options{TamperEvident: true, SessionID: "large"})
	big := strings.Repeat("x", 2*1024*1024)
	if err := w.Write(Event{
		Timestamp: "2026-01-01T00:00:00Z",
		CallID:    "c1",
		Tool:      "filesystem.write",
		Decision:  policy.DecisionAllow,
		Reason:    "allowed",
		Arguments: map[string]interface{}{"blob": big},
	}); err != nil {
		t.Fatalf("Write large event: %v", err)
	}
	if buf.Len() < 2*1024*1024 {
		t.Fatalf("setup: serialized event smaller than expected (%d)", buf.Len())
	}
	n, err := VerifyChain(buf)
	if err != nil {
		t.Fatalf("VerifyChain on large event: %v", err)
	}
	if n != 1 {
		t.Errorf("verified count = %d, want 1", n)
	}
}

func TestVerifyChainAcceptsLineWithoutTrailingNewline(t *testing.T) {
	log, _ := buildChainedLog(t, 2)
	noTrailing := bytes.TrimRight(log, "\n")
	n, err := VerifyChain(bytes.NewReader(noTrailing))
	if err != nil {
		t.Fatalf("VerifyChain without trailing newline: %v", err)
	}
	if n != 2 {
		t.Errorf("verified count = %d, want 2", n)
	}
}
