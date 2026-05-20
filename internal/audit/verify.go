package audit

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// ErrNoChain is returned by VerifyChain when no event in the log carried a
// hash chain field. The audit log is parseable, but it was not written in
// tamper-evident mode and integrity cannot be verified.
var ErrNoChain = errors.New("audit: log was not written with tamper-evident chaining")

// VerifyError describes a chain-integrity failure at a specific event.
//
// EventNumber is 1-indexed and refers to event position in the input, not the
// Sequence field on the event itself. The two should match when the writer
// has not been tampered with.
type VerifyError struct {
	EventNumber int
	Reason      string
}

func (e *VerifyError) Error() string {
	return fmt.Sprintf("audit: event %d: %s", e.EventNumber, e.Reason)
}

// VerifyChain reads JSONL audit events from r and verifies the tamper-evident
// hash chain.
//
// Returns the number of events read on success, regardless of whether they were
// chained. If the log was not written with tamper-evident chaining (no event
// carried prev_hash or hash fields), it returns ErrNoChain alongside the event
// count. If chain verification fails, it returns a *VerifyError pinpointing the
// offending event. Other errors (I/O, malformed JSON) are wrapped and returned.
func VerifyChain(r io.Reader) (int, error) {
	scanner := bufio.NewScanner(r)
	// Audit events with large argument payloads can exceed bufio's default 64KB
	// line limit; bump it to 1 MiB which is still bounded.
	const maxLineBytes = 1 << 20
	scanner.Buffer(make([]byte, 0, 64*1024), maxLineBytes)

	var (
		prevHash    string
		eventNumber int
		anyChained  bool
	)

	for scanner.Scan() {
		eventNumber++
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		var e Event
		if err := json.Unmarshal(line, &e); err != nil {
			return eventNumber, &VerifyError{
				EventNumber: eventNumber,
				Reason:      fmt.Sprintf("invalid JSON: %s", err),
			}
		}

		// A log is chained as soon as ANY event carries hash fields. Events
		// without hash fields after that point are a tamper signal.
		if e.Hash != "" || e.PrevHash != "" {
			anyChained = true
		} else if anyChained {
			return eventNumber, &VerifyError{
				EventNumber: eventNumber,
				Reason:      "event is missing hash fields in a chained log (possible truncation or tampering)",
			}
		} else {
			// Not chained at all yet; just count and move on.
			continue
		}

		// Re-compute the hash over the event with the Hash field zeroed,
		// exactly as the writer did.
		claimed := e.Hash
		e.Hash = ""
		recomputed, err := hashEvent(e)
		if err != nil {
			return eventNumber, fmt.Errorf("audit: event %d: recompute hash: %w", eventNumber, err)
		}
		if recomputed != claimed {
			return eventNumber, &VerifyError{
				EventNumber: eventNumber,
				Reason:      fmt.Sprintf("hash mismatch: claimed %q, recomputed %q", claimed, recomputed),
			}
		}
		if e.PrevHash != prevHash {
			return eventNumber, &VerifyError{
				EventNumber: eventNumber,
				Reason:      fmt.Sprintf("prev_hash mismatch: event records %q, previous event's hash was %q", e.PrevHash, prevHash),
			}
		}

		prevHash = claimed
	}

	if err := scanner.Err(); err != nil {
		return eventNumber, fmt.Errorf("audit: read input: %w", err)
	}

	if !anyChained {
		return eventNumber, ErrNoChain
	}
	return eventNumber, nil
}
