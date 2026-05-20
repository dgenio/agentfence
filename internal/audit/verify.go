package audit

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// ErrNoChain is returned by VerifyChain when at least one event is present but
// no event carried a hash chain field. The audit log is parseable, but it was
// not written in tamper-evident mode and integrity cannot be verified.
//
// An empty input (no events at all) returns (0, nil), not ErrNoChain.
var ErrNoChain = errors.New("audit: log was not written with tamper-evident chaining")

// VerifyError describes a chain-integrity failure at a specific event.
//
// EventNumber is the 1-based position of the offending event in the input,
// counting only non-blank lines. Blank/whitespace-only lines are skipped and
// do not advance the counter.
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
// Returns the number of non-blank events read on success, regardless of
// whether they were chained:
//
//   - Empty input (no events): returns (0, nil).
//   - At least one event but none chained: returns (n, ErrNoChain).
//   - Modification/deletion/reordering: returns (n, *VerifyError) where
//     EventNumber pinpoints the offending event.
//   - I/O or malformed JSON: returns a wrapped error or *VerifyError.
//
// VerifyChain uses bufio.Reader.ReadBytes so individual events may be
// arbitrarily large (bounded only by available memory).
func VerifyChain(r io.Reader) (int, error) {
	br := bufio.NewReader(r)

	var (
		prevHash    string
		eventNumber int
		anyChained  bool
	)

	for {
		line, readErr := br.ReadBytes('\n')
		// ReadBytes returns the data read so far together with io.EOF if the
		// input did not end with a newline. Process the partial line first,
		// then exit the loop.

		line = bytes.TrimRight(line, "\r\n")
		if len(bytes.TrimSpace(line)) == 0 {
			if readErr != nil {
				if errors.Is(readErr, io.EOF) {
					break
				}
				return eventNumber, fmt.Errorf("audit: read input: %w", readErr)
			}
			continue
		}

		eventNumber++

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
			if readErr != nil {
				if errors.Is(readErr, io.EOF) {
					break
				}
				return eventNumber, fmt.Errorf("audit: read input: %w", readErr)
			}
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

		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				break
			}
			return eventNumber, fmt.Errorf("audit: read input: %w", readErr)
		}
	}

	switch {
	case eventNumber == 0:
		// Empty input: nothing to verify, nothing to complain about.
		return 0, nil
	case !anyChained:
		return eventNumber, ErrNoChain
	default:
		return eventNumber, nil
	}
}
