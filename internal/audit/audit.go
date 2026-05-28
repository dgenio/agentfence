package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/dgenio/agentfence/internal/policy"
)

// CurrentSchemaVersion is the schema_version value written into every Event.
// Bump this when the on-wire layout changes in a way that downstream parsers
// must distinguish.
//
// History:
//
//	"1" — initial schema with session_id, seq, optional hash chain.
//	"2" — added optional "mode" field ("dry_run" for simulated enforcement)
//	      and optional "memory_write" summary for durable-memory-write events.
const CurrentSchemaVersion = "2"

// ModeDryRun marks an audit event produced under dry-run evaluation. Events
// without an explicit Mode are treated as enforced.
const ModeDryRun = "dry_run"

// MemoryWriteSummary is a safe-to-log summary of a durable memory-write tool
// call. It captures the dimensions a policy cares about — scope, sensitivity,
// payload size — and a collision-resistant fingerprint of the raw payload,
// without including the payload itself.
type MemoryWriteSummary struct {
	// Scope is the effective scope used during evaluation: one of session,
	// project, global. Missing scope arguments default to session.
	Scope string `json:"scope,omitempty"`
	// Sensitivity is the resolved sensitivity (low, medium, high) used
	// during evaluation.
	Sensitivity string `json:"sensitivity,omitempty"`
	// Field is the argument key that held the durable payload (e.g. "value").
	Field string `json:"field,omitempty"`
	// SizeBytes is the byte length of the payload as evaluated.
	SizeBytes int `json:"size_bytes"`
	// ContentFingerprint is a short SHA-256 prefix of the payload, suitable
	// for de-duplication and forensic correlation. Never reveals payload
	// contents.
	ContentFingerprint string `json:"content_fingerprint,omitempty"`
	// PatternsMatched lists the redaction-pattern names that matched the
	// payload. Empty when none matched (and sensitivity was not declared).
	PatternsMatched []string `json:"patterns_matched,omitempty"`
}

// Event is a single audit record written to the JSONL stream.
//
// SchemaVersion, SessionID, and Sequence are populated by Writer.Write so callers
// constructing events directly do not need to set them.
//
// PrevHash and Hash are populated only when the Writer is configured with
// TamperEvident=true. They form a hash chain so log tampering can be detected
// after the fact by VerifyChain.
type Event struct {
	SchemaVersion string                 `json:"schema_version"`
	SessionID     string                 `json:"session_id"`
	Sequence      uint64                 `json:"seq"`
	Timestamp     string                 `json:"timestamp"`
	CallID        string                 `json:"call_id"`
	Tool          string                 `json:"tool"`
	Decision      policy.Decision        `json:"decision"`
	Reason        string                 `json:"reason"`
	Arguments     map[string]interface{} `json:"arguments,omitempty"`
	MemoryWrite   *MemoryWriteSummary    `json:"memory_write,omitempty"`
	Mode          string                 `json:"mode,omitempty"`
	PrevHash      string                 `json:"prev_hash,omitempty"`
	Hash          string                 `json:"hash,omitempty"`
}

// Options configures a Writer's per-session and chain behaviour.
type Options struct {
	// TamperEvident enables hash chaining. Each event's prev_hash field is set
	// to the previous event's hash, and each event records its own hash.
	TamperEvident bool

	// SessionID overrides the auto-generated session ID. Intended for tests.
	SessionID string

	// InitialPrevHash seeds the hash chain when appending to an existing
	// tamper-evident log. Leave empty for a new chain.
	InitialPrevHash string
}

// Writer serialises Events as newline-delimited JSON. It owns the per-session
// fields (SchemaVersion, SessionID, Sequence) and the hash chain state when
// tamper-evident mode is on. Writes are safe for concurrent use.
type Writer struct {
	mu            sync.Mutex
	w             io.Writer
	sessionID     string
	seq           uint64
	tamperEvident bool
	prevHash      string
}

// NewWriter returns a Writer that does not chain events.
//
// It is equivalent to NewWriterOptions(w, Options{}).
func NewWriter(w io.Writer) *Writer {
	return NewWriterOptions(w, Options{})
}

// NewWriterOptions returns a Writer configured by opts. A random UUIDv4 is
// generated for SessionID unless Options.SessionID is set.
func NewWriterOptions(w io.Writer, opts Options) *Writer {
	sid := opts.SessionID
	if sid == "" {
		sid = uuid.NewString()
	}
	return &Writer{
		w:             w,
		sessionID:     sid,
		tamperEvident: opts.TamperEvident,
		prevHash:      opts.InitialPrevHash,
	}
}

// SessionID returns the writer's session identifier. Useful for tests and for
// callers that want to record the session ID separately.
func (w *Writer) SessionID() string {
	return w.sessionID
}

// NewEvent creates an Event from an evaluated tool call. The Writer fills in
// SchemaVersion, SessionID, Sequence, and (if tamper-evident) PrevHash/Hash.
func NewEvent(call policy.ToolCall, result policy.EvaluationResult, redacted map[string]interface{}, includeArgs bool) Event {
	e := Event{
		Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
		CallID:    call.ID,
		Tool:      call.Tool,
		Decision:  result.Decision,
		Reason:    result.Reason,
	}
	if includeArgs {
		e.Arguments = redacted
	}
	return e
}

// Write serialises event to the underlying writer as a single JSONL line.
//
// The caller may leave SchemaVersion/SessionID/Sequence/PrevHash/Hash zero;
// Write populates them deterministically.
//
// The sequence counter and chain state advance only after the event has been
// successfully serialised and written. If hashing, marshalling, or the
// underlying writer fail, neither w.seq nor w.prevHash move, so retries do
// not produce gaps or break the chain.
func (w *Writer) Write(event Event) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	nextSeq := w.seq + 1
	event.SchemaVersion = CurrentSchemaVersion
	event.SessionID = w.sessionID
	event.Sequence = nextSeq

	if w.tamperEvident {
		event.PrevHash = w.prevHash
		event.Hash = "" // hash is computed over the event with Hash="" to avoid self-reference
		h, err := hashEvent(event)
		if err != nil {
			return fmt.Errorf("audit: hash event: %w", err)
		}
		event.Hash = h
	}

	b, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("audit: marshal event: %w", err)
	}
	if _, err := w.w.Write(append(b, '\n')); err != nil {
		return err
	}

	// Commit state only after a successful write.
	w.seq = nextSeq
	if w.tamperEvident {
		w.prevHash = event.Hash
	}
	return nil
}

// NewErrorEvent creates a synthetic deny audit event for a line that failed to parse.
func NewErrorEvent(line int, reason string) Event {
	return Event{
		Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
		CallID:    fmt.Sprintf("line-%d", line),
		Tool:      "",
		Decision:  policy.DecisionDeny,
		Reason:    "parse error: " + reason,
	}
}

// hashEvent returns the hex-encoded SHA-256 of the canonical JSON encoding of
// e. The Hash field of e MUST be empty when calling this (otherwise the hash
// would depend on itself).
//
// encoding/json sorts map keys alphabetically and emits struct fields in their
// declaration order, so the resulting bytes are deterministic across writers
// for the same logical event.
func hashEvent(e Event) (string, error) {
	if e.Hash != "" {
		return "", fmt.Errorf("audit: hashEvent called with non-empty Hash field")
	}
	b, err := json.Marshal(e)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}
