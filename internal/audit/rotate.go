package audit

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// RotationConfig configures size- and age-based rotation of a file-backed audit
// log. A zero MaxSizeBytes disables size rotation; a zero MaxAge disables age
// rotation; both zero means the Rotator behaves like a plain append file.
type RotationConfig struct {
	// Path is the active segment file. Rotated segments are renamed to
	// "<Path>.<UTC-timestamp>".
	Path string
	// MaxSizeBytes rotates the active segment once it reaches this many bytes.
	MaxSizeBytes int64
	// MaxAge rotates the active segment once it has been open this long.
	MaxAge time.Duration
	// Keep bounds how many rotated segments are retained. Older segments beyond
	// Keep are deleted after each rotation. Zero keeps every segment.
	Keep int
	// now is injected in tests; production uses time.Now.
	now func() time.Time
}

// Rotator is an io.WriteCloser that appends audit JSONL to an active segment
// file and rolls over to a new segment when the configured size or age
// threshold is reached. Each segment starts a fresh hash chain (the Writer
// clears prev_hash on rotation), so every rotated file is independently
// verifiable by `audit verify`.
//
// A Rotator is written to exclusively by a single audit.Writer, which
// serialises calls under its own mutex; the internal mutex guards against
// concurrent Close.
type Rotator struct {
	mu       sync.Mutex
	cfg      RotationConfig
	f        *os.File
	size     int64
	openedAt time.Time
}

// NewRotator opens (creating if needed) the active segment at cfg.Path in
// append mode with 0o600 permissions and returns a ready Rotator.
func NewRotator(cfg RotationConfig) (*Rotator, error) {
	if cfg.Path == "" {
		return nil, fmt.Errorf("audit: rotation requires a log path")
	}
	if cfg.now == nil {
		cfg.now = time.Now
	}
	f, err := os.OpenFile(cfg.Path, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return nil, err
	}
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	return &Rotator{
		cfg:      cfg,
		f:        f,
		size:     info.Size(),
		openedAt: cfg.now(),
	}, nil
}

// Write appends p to the active segment, tracking its byte count.
func (r *Rotator) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.f == nil {
		return 0, os.ErrClosed
	}
	n, err := r.f.Write(p)
	r.size += int64(n)
	return n, err
}

// Close closes the active segment.
func (r *Rotator) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.f == nil {
		return nil
	}
	err := r.f.Close()
	r.f = nil
	return err
}

// ResumeState reads the active segment's existing chain so a restart can
// continue (rather than fork) the chain in the current segment. It mirrors
// LastChainState and leaves the file positioned for appending.
func (r *Rotator) ResumeState() (lastHash string, eventCount int, firstChained int, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.f == nil {
		return "", 0, 0, os.ErrClosed
	}
	if _, err := r.f.Seek(0, io.SeekStart); err != nil {
		return "", 0, 0, err
	}
	lastHash, eventCount, firstChained, err = LastChainState(r.f)
	if err != nil {
		return "", 0, 0, err
	}
	if _, serr := r.f.Seek(0, io.SeekEnd); serr != nil {
		return "", 0, 0, serr
	}
	return lastHash, eventCount, firstChained, nil
}

// maybeRotate rolls the active segment over when it is non-empty and has
// reached the size or age threshold. It reports whether a rotation occurred so
// the Writer can start a new chain. An empty segment is never rotated.
func (r *Rotator) maybeRotate() (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.f == nil {
		return false, os.ErrClosed
	}
	if r.size == 0 {
		return false, nil
	}
	over := false
	if r.cfg.MaxSizeBytes > 0 && r.size >= r.cfg.MaxSizeBytes {
		over = true
	}
	if !over && r.cfg.MaxAge > 0 && r.cfg.now().Sub(r.openedAt) >= r.cfg.MaxAge {
		over = true
	}
	if !over {
		return false, nil
	}

	if err := r.f.Close(); err != nil {
		r.f = nil
		return false, err
	}
	r.f = nil

	dest := r.rotatedName(r.cfg.now())
	if err := os.Rename(r.cfg.Path, dest); err != nil {
		return false, fmt.Errorf("audit: rename segment: %w", err)
	}

	f, err := os.OpenFile(r.cfg.Path, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return false, err
	}
	r.f = f
	r.size = 0
	r.openedAt = r.cfg.now()

	r.prune()
	return true, nil
}

// rotatedName returns a collision-free "<Path>.<timestamp>" for a segment
// rotated at t. The timestamp is zero-padded UTC so lexical and chronological
// order agree, which keeps prune simple.
func (r *Rotator) rotatedName(t time.Time) string {
	base := fmt.Sprintf("%s.%s", r.cfg.Path, t.UTC().Format("20060102T150405.000000000Z"))
	name := base
	for i := 1; ; i++ {
		if _, err := os.Stat(name); os.IsNotExist(err) {
			return name
		}
		name = fmt.Sprintf("%s.%d", base, i)
	}
}

// prune deletes rotated segments beyond cfg.Keep, oldest first. Keep <= 0
// retains everything.
func (r *Rotator) prune() {
	if r.cfg.Keep <= 0 {
		return
	}
	matches, err := filepath.Glob(r.cfg.Path + ".*")
	if err != nil {
		return
	}
	if len(matches) <= r.cfg.Keep {
		return
	}
	sort.Strings(matches) // chronological, thanks to the zero-padded suffix
	for _, old := range matches[:len(matches)-r.cfg.Keep] {
		_ = os.Remove(old)
	}
}
