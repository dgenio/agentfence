package audit

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/dgenio/agentfence/internal/policy"
)

func countSegments(t *testing.T, path string) int {
	t.Helper()
	matches, err := filepath.Glob(path + ".*")
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	return len(matches)
}

func TestRotatorSizeRotation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	rot, err := NewRotator(RotationConfig{Path: path, MaxSizeBytes: 200, Keep: 10})
	if err != nil {
		t.Fatalf("NewRotator: %v", err)
	}
	defer rot.Close()

	w := NewWriterOptions(rot, Options{TamperEvident: true, Rotator: rot, SessionID: "s"})
	for i := 0; i < 20; i++ {
		if err := w.Write(Event{CallID: "c", Tool: "filesystem.read", Decision: policy.DecisionAllow, Reason: "ok"}); err != nil {
			t.Fatalf("Write: %v", err)
		}
	}
	if n := countSegments(t, path); n == 0 {
		t.Fatal("expected at least one rotated segment")
	}

	// Every rotated segment must be independently verifiable (fresh chain root).
	matches, _ := filepath.Glob(path + ".*")
	for _, seg := range matches {
		f, err := os.Open(seg)
		if err != nil {
			t.Fatal(err)
		}
		n, err := VerifyChain(f)
		f.Close()
		if err != nil {
			t.Fatalf("segment %s failed to verify: %v", seg, err)
		}
		if n == 0 {
			t.Fatalf("segment %s had no events", seg)
		}
	}
}

func TestRotatorAgeRotation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	now := time.Unix(0, 0)
	rot, err := NewRotator(RotationConfig{
		Path:   path,
		MaxAge: time.Minute,
		Keep:   10,
		now:    func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewRotator: %v", err)
	}
	defer rot.Close()

	w := NewWriterOptions(rot, Options{Rotator: rot})
	if err := w.Write(Event{CallID: "c1", Tool: "t", Decision: policy.DecisionAllow}); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if got := countSegments(t, path); got != 0 {
		t.Fatalf("no rotation expected yet, got %d segments", got)
	}
	// Advance the clock past MaxAge; the next write rotates.
	now = now.Add(2 * time.Minute)
	if err := w.Write(Event{CallID: "c2", Tool: "t", Decision: policy.DecisionAllow}); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if got := countSegments(t, path); got != 1 {
		t.Fatalf("expected exactly 1 rotated segment after age rollover, got %d", got)
	}
}

func TestRotatorRetentionPrunesOldSegments(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	rot, err := NewRotator(RotationConfig{Path: path, MaxSizeBytes: 1, Keep: 2})
	if err != nil {
		t.Fatalf("NewRotator: %v", err)
	}
	defer rot.Close()

	w := NewWriterOptions(rot, Options{Rotator: rot})
	// MaxSizeBytes:1 forces a rotation before every event after the first.
	for i := 0; i < 6; i++ {
		if err := w.Write(Event{CallID: "c", Tool: "t", Decision: policy.DecisionAllow}); err != nil {
			t.Fatalf("Write: %v", err)
		}
	}
	if got := countSegments(t, path); got > 2 {
		t.Fatalf("retention should cap rotated segments at Keep=2, got %d", got)
	}
}

func TestRotatorEmptySegmentNotRotated(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	rot, err := NewRotator(RotationConfig{Path: path, MaxSizeBytes: 1, Keep: 5})
	if err != nil {
		t.Fatalf("NewRotator: %v", err)
	}
	defer rot.Close()
	// No writes yet: maybeRotate must be a no-op on an empty segment.
	rotated, err := rot.maybeRotate()
	if err != nil {
		t.Fatalf("maybeRotate: %v", err)
	}
	if rotated {
		t.Fatal("an empty segment must not rotate")
	}
}
