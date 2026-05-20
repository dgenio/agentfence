package audit

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
	"sync"
	"testing"

	"github.com/dgenio/agentfence/internal/policy"
)

func TestWriteJSONL(t *testing.T) {
	buf := &bytes.Buffer{}
	w := NewWriter(buf)
	e := Event{
		Timestamp: "2026-01-01T00:00:00Z",
		CallID:    "call_1",
		Tool:      "filesystem.read",
		Decision:  policy.DecisionAllow,
		Reason:    "allowed",
		Arguments: map[string]interface{}{"path": "README.md"},
	}
	if err := w.Write(e); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	line := strings.TrimSpace(buf.String())
	var out map[string]interface{}
	if err := json.Unmarshal([]byte(line), &out); err != nil {
		t.Fatalf("invalid JSON output: %v", err)
	}
	if out["decision"] != string(policy.DecisionAllow) {
		t.Fatalf("expected decision allow, got %v", out["decision"])
	}
}

// ── #31: schema version, session id, sequence ─────────────────────────────────

func TestWriteAddsSchemaFields(t *testing.T) {
	buf := &bytes.Buffer{}
	w := NewWriter(buf)
	if err := w.Write(Event{CallID: "c1", Tool: "t", Decision: policy.DecisionAllow}); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	var out Event
	if err := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &out); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if out.SchemaVersion != CurrentSchemaVersion {
		t.Errorf("schema_version = %q, want %q", out.SchemaVersion, CurrentSchemaVersion)
	}
	if out.SessionID == "" {
		t.Error("session_id was empty")
	}
	if out.Sequence != 1 {
		t.Errorf("seq = %d, want 1", out.Sequence)
	}
}

func TestSessionIDIsStableAcrossWrites(t *testing.T) {
	buf := &bytes.Buffer{}
	w := NewWriter(buf)
	for i := 0; i < 3; i++ {
		if err := w.Write(Event{CallID: "c", Tool: "t", Decision: policy.DecisionAllow}); err != nil {
			t.Fatalf("Write() error = %v", err)
		}
	}
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 3 {
		t.Fatalf("expected 3 lines, got %d", len(lines))
	}
	var sids []string
	for _, line := range lines {
		var e Event
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatalf("invalid JSON: %v", err)
		}
		sids = append(sids, e.SessionID)
	}
	if sids[0] != sids[1] || sids[1] != sids[2] {
		t.Errorf("session_id drifted across writes: %v", sids)
	}
}

func TestSessionIDIsUniqueAcrossWriters(t *testing.T) {
	a := NewWriter(&bytes.Buffer{})
	b := NewWriter(&bytes.Buffer{})
	if a.SessionID() == b.SessionID() {
		t.Fatal("expected distinct session ids for distinct Writers")
	}
}

func TestSequenceIsMonotonic(t *testing.T) {
	buf := &bytes.Buffer{}
	w := NewWriter(buf)
	for i := 0; i < 5; i++ {
		if err := w.Write(Event{CallID: "c", Tool: "t", Decision: policy.DecisionAllow}); err != nil {
			t.Fatalf("Write() error = %v", err)
		}
	}
	for i, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		var e Event
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatalf("invalid JSON: %v", err)
		}
		want := uint64(i + 1)
		if e.Sequence != want {
			t.Errorf("event %d: seq = %d, want %d", i, e.Sequence, want)
		}
	}
}

func TestWriterIsConcurrencySafe(t *testing.T) {
	buf := &bytes.Buffer{}
	w := NewWriter(buf)
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = w.Write(Event{CallID: "c", Tool: "t", Decision: policy.DecisionAllow})
		}()
	}
	wg.Wait()
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 50 {
		t.Fatalf("expected 50 lines, got %d", len(lines))
	}
	seen := make(map[uint64]bool, 50)
	for _, line := range lines {
		var e Event
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatalf("invalid JSON: %v", err)
		}
		if seen[e.Sequence] {
			t.Fatalf("duplicate sequence %d", e.Sequence)
		}
		seen[e.Sequence] = true
	}
	for i := uint64(1); i <= 50; i++ {
		if !seen[i] {
			t.Fatalf("missing sequence %d", i)
		}
	}
}

// ── #33: tamper-evident hash chain ────────────────────────────────────────────

func TestTamperEvidentChainStart(t *testing.T) {
	buf := &bytes.Buffer{}
	w := NewWriterOptions(buf, Options{TamperEvident: true})
	if err := w.Write(Event{CallID: "c1", Tool: "t", Decision: policy.DecisionAllow}); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	var e Event
	if err := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &e); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if e.PrevHash != "" {
		t.Errorf("first event prev_hash = %q, want empty", e.PrevHash)
	}
	if e.Hash == "" {
		t.Error("first event hash was empty")
	}
	if len(e.Hash) != 64 {
		t.Errorf("hash length = %d, want 64 hex chars (sha256)", len(e.Hash))
	}
}

func TestTamperEvidentChainLinks(t *testing.T) {
	buf := &bytes.Buffer{}
	w := NewWriterOptions(buf, Options{TamperEvident: true})
	for i := 0; i < 4; i++ {
		if err := w.Write(Event{CallID: "c", Tool: "t", Decision: policy.DecisionAllow}); err != nil {
			t.Fatalf("Write() error = %v", err)
		}
	}
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	var prev string
	for i, line := range lines {
		var e Event
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatalf("invalid JSON: %v", err)
		}
		if e.PrevHash != prev {
			t.Errorf("event %d: prev_hash = %q, want %q", i, e.PrevHash, prev)
		}
		if e.Hash == "" {
			t.Errorf("event %d: hash was empty", i)
		}
		prev = e.Hash
	}
}

func TestTamperEvidentHashIsDeterministic(t *testing.T) {
	mk := func() Event {
		return Event{
			CallID:    "c1",
			Tool:      "filesystem.read",
			Decision:  policy.DecisionAllow,
			Reason:    "allowed",
			Arguments: map[string]interface{}{"path": "README.md", "mode": "r"},
		}
	}
	buf1, buf2 := &bytes.Buffer{}, &bytes.Buffer{}
	w1 := NewWriterOptions(buf1, Options{TamperEvident: true, SessionID: "fixed-session"})
	w2 := NewWriterOptions(buf2, Options{TamperEvident: true, SessionID: "fixed-session"})
	e1 := mk()
	e1.Timestamp = "2026-01-01T00:00:00Z"
	e2 := e1
	if err := w1.Write(e1); err != nil {
		t.Fatalf("w1.Write: %v", err)
	}
	if err := w2.Write(e2); err != nil {
		t.Fatalf("w2.Write: %v", err)
	}
	if !bytes.Equal(buf1.Bytes(), buf2.Bytes()) {
		t.Fatalf("non-deterministic serialization:\n a=%s\n b=%s", buf1, buf2)
	}
}

func TestNonTamperEvidentOmitsChainFields(t *testing.T) {
	buf := &bytes.Buffer{}
	w := NewWriter(buf) // not tamper-evident
	if err := w.Write(Event{CallID: "c1", Tool: "t", Decision: policy.DecisionAllow}); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	if bytes.Contains(buf.Bytes(), []byte("prev_hash")) {
		t.Errorf("non-tamper-evident output should not contain prev_hash: %s", buf.String())
	}
	if bytes.Contains(buf.Bytes(), []byte("\"hash\"")) {
		t.Errorf("non-tamper-evident output should not contain hash: %s", buf.String())
	}
}

func TestHashEventRejectsNonEmptyHashField(t *testing.T) {
	e := Event{CallID: "c", Hash: "already-set"}
	if _, err := hashEvent(e); err == nil {
		t.Fatal("expected hashEvent to reject pre-set Hash field")
	}
}

// failingWriter returns an error after `okWrites` successful Write calls. This
// simulates a transient I/O failure (disk full, broken pipe, etc.) to verify
// the audit Writer does not advance its sequence counter or chain state when
// the underlying writer fails.
type failingWriter struct {
	okWrites int
	calls    int
}

func (f *failingWriter) Write(p []byte) (int, error) {
	f.calls++
	if f.calls > f.okWrites {
		return 0, io.ErrClosedPipe
	}
	return len(p), nil
}

func TestWriteFailureDoesNotAdvanceSequence(t *testing.T) {
	fw := &failingWriter{okWrites: 1}
	w := NewWriter(fw)
	if err := w.Write(Event{CallID: "c1", Tool: "t", Decision: policy.DecisionAllow}); err != nil {
		t.Fatalf("first Write unexpected error: %v", err)
	}
	if w.seq != 1 {
		t.Fatalf("seq after first Write = %d, want 1", w.seq)
	}
	if err := w.Write(Event{CallID: "c2", Tool: "t", Decision: policy.DecisionAllow}); err == nil {
		t.Fatal("expected error from failing writer on second Write")
	}
	if w.seq != 1 {
		t.Errorf("seq advanced to %d after failed Write, want 1", w.seq)
	}
}

func TestWriteFailureDoesNotAdvanceChainState(t *testing.T) {
	fw := &failingWriter{okWrites: 1}
	w := NewWriterOptions(fw, Options{TamperEvident: true, SessionID: "test"})
	if err := w.Write(Event{CallID: "c1", Tool: "t", Decision: policy.DecisionAllow}); err != nil {
		t.Fatalf("first Write unexpected error: %v", err)
	}
	firstHash := w.prevHash
	if firstHash == "" {
		t.Fatal("first Write did not record prevHash")
	}
	if err := w.Write(Event{CallID: "c2", Tool: "t", Decision: policy.DecisionAllow}); err == nil {
		t.Fatal("expected error from failing writer on second Write")
	}
	if w.prevHash != firstHash {
		t.Errorf("prevHash changed after failed Write: was %q, now %q", firstHash, w.prevHash)
	}
}
