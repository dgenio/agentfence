package audit

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dgenio/agentfence/internal/policy"
)

// countingSyncer is an io.Writer that also records how many times Sync was
// called, so durability tests can assert the Writer flushes when (and only
// when) it should.
type countingSyncer struct {
	bytes.Buffer
	syncs   int
	syncErr error
}

func (c *countingSyncer) Sync() error {
	c.syncs++
	return c.syncErr
}

func TestWriterFsyncSyncsEveryWrite(t *testing.T) {
	dst := &countingSyncer{}
	w := NewWriterOptions(dst, Options{Fsync: true})
	for i := 0; i < 3; i++ {
		if err := w.Write(Event{CallID: "c", Tool: "t", Decision: policy.DecisionAllow}); err != nil {
			t.Fatalf("Write() error = %v", err)
		}
	}
	if dst.syncs != 3 {
		t.Fatalf("Sync called %d times, want 3 (one per write)", dst.syncs)
	}
}

func TestWriterWithoutFsyncNeverSyncs(t *testing.T) {
	dst := &countingSyncer{}
	w := NewWriterOptions(dst, Options{})
	if err := w.Write(Event{CallID: "c", Tool: "t", Decision: policy.DecisionAllow}); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	if dst.syncs != 0 {
		t.Fatalf("Sync called %d times, want 0 without Fsync", dst.syncs)
	}
}

func TestWriterSyncFlushesDestination(t *testing.T) {
	dst := &countingSyncer{}
	w := NewWriterOptions(dst, Options{})
	if err := w.Sync(); err != nil {
		t.Fatalf("Sync() error = %v", err)
	}
	if dst.syncs != 1 {
		t.Fatalf("Sync called %d times, want 1", dst.syncs)
	}
}

func TestWriterSyncNoopOnPlainWriter(t *testing.T) {
	// A destination that cannot Sync (an in-memory buffer) must make Sync a
	// no-op, not an error: --audit-fsync against stdout/discard is harmless.
	w := NewWriter(&bytes.Buffer{})
	if err := w.Sync(); err != nil {
		t.Fatalf("Sync() on non-syncing writer error = %v, want nil", err)
	}
}

func TestWriterFsyncErrorPropagatesButLineIsWritten(t *testing.T) {
	sentinel := errors.New("disk full")
	dst := &countingSyncer{syncErr: sentinel}
	w := NewWriterOptions(dst, Options{Fsync: true})

	err := w.Write(Event{CallID: "c", Tool: "t", Decision: policy.DecisionAllow})
	if !errors.Is(err, sentinel) {
		t.Fatalf("Write() error = %v, want it to wrap %v", err, sentinel)
	}
	// The line is already committed to the buffer; an fsync failure is a
	// durability warning, not a reason to drop the record.
	if strings.Count(strings.TrimSpace(dst.String()), "\n") != 0 || dst.Len() == 0 {
		t.Fatalf("expected exactly one written line despite fsync error, got %q", dst.String())
	}
}

func TestRotatorSync(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	rot, err := NewRotator(RotationConfig{Path: path})
	if err != nil {
		t.Fatalf("NewRotator: %v", err)
	}
	if _, err := rot.Write([]byte("line\n")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := rot.Sync(); err != nil {
		t.Fatalf("Sync() error = %v", err)
	}
	if err := rot.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := rot.Sync(); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("Sync() after Close = %v, want os.ErrClosed", err)
	}
}

// TestWriterFsyncThroughRotatorIsDurable proves the Fsync option reaches a
// rotating destination (the path the proxies use with --audit-max-size), so a
// rotated log is as durable as a plain one.
func TestWriterFsyncThroughRotatorIsDurable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	rot, err := NewRotator(RotationConfig{Path: path})
	if err != nil {
		t.Fatalf("NewRotator: %v", err)
	}
	defer rot.Close()

	w := NewWriterOptions(rot, Options{Fsync: true})
	if err := w.Write(Event{CallID: "c", Tool: "t", Decision: policy.DecisionAllow}); err != nil {
		t.Fatalf("Write: %v", err)
	}
	// The event must be readable from disk immediately (it was flushed).
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if !bytes.Contains(b, []byte(`"call_id":"c"`)) {
		t.Fatalf("event not durably written: %q", b)
	}
}
