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

// ErrPartialChain is the sentinel returned by VerifyChain when a log mixes
// unchained events with chained events: the suffix is tamper-evident but the
// prefix is not. Operators relying on `audit verify` to attest full-log
// integrity need to see this distinct from a fully chained "OK" result.
//
// VerifyChain wraps ErrPartialChain inside a *PartialChainError that carries
// the total event count and the 1-based position where the chain started.
var ErrPartialChain = errors.New("audit: log mixes unchained and chained events; prefix is not integrity-protected")

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

// PartialChainError describes a log whose chain does not cover every event.
// Total is the number of non-blank events parsed. ChainStartEvent is the
// 1-based position of the first chained event (always > 1 when this error is
// returned; for ChainStartEvent == 1 the chain is full and no error occurs).
type PartialChainError struct {
	Total           int
	ChainStartEvent int
}

func (e *PartialChainError) Error() string {
	return fmt.Sprintf("audit: chain starts at event %d of %d; events 1..%d are not integrity-protected", e.ChainStartEvent, e.Total, e.ChainStartEvent-1)
}

// Unwrap lets callers match this error with errors.Is(err, ErrPartialChain).
func (e *PartialChainError) Unwrap() error { return ErrPartialChain }

// VerifyChain reads JSONL audit events from r and verifies the tamper-evident
// hash chain.
//
// Returns the number of non-blank events read on success, regardless of
// whether they were chained:
//
//   - Empty input (no events): returns (0, nil).
//   - At least one event but none chained: returns (n, ErrNoChain).
//   - Mixed: chain present but does not cover every event (unchained prefix):
//     returns (n, *PartialChainError). errors.Is(err, ErrPartialChain) matches.
//   - Modification/deletion/reordering: returns (n, *VerifyError) where
//     EventNumber pinpoints the offending event.
//   - I/O or malformed JSON: returns a wrapped error or *VerifyError.
//
// VerifyChain uses bufio.Reader.ReadBytes so individual events may be
// arbitrarily large (bounded only by available memory).
func VerifyChain(r io.Reader) (int, error) {
	eventNumber, _, firstChained, err := verifyChain(r)
	switch {
	case err != nil:
		return eventNumber, err
	case eventNumber == 0:
		// Empty input: nothing to verify, nothing to complain about.
		return 0, nil
	case firstChained == 0:
		return eventNumber, ErrNoChain
	case firstChained > 1:
		return eventNumber, &PartialChainError{Total: eventNumber, ChainStartEvent: firstChained}
	default:
		return eventNumber, nil
	}
}

// LastChainHash verifies r like VerifyChain and returns the last chained
// event's hash. It returns an empty hash for empty or entirely unchained logs.
//
// LastChainHash treats a partial chain as a successful read for the purposes
// of returning the last hash: appending to a mixed log must continue the
// existing suffix's chain, even though `audit verify` will surface the
// partial-chain status separately.
func LastChainHash(r io.Reader) (string, error) {
	_, lastHash, _, err := verifyChain(r)
	return lastHash, err
}

// LastChainState is the writer-side companion to VerifyChain. It returns the
// last chained event's hash, the total non-blank event count, and the 1-based
// position of the first chained event (0 if none).
//
// openAuditOutput uses this to refuse `--tamper-evident` on a non-empty log
// that has no chain at all, which would otherwise produce a mixed log that
// `audit verify` cannot fully attest.
func LastChainState(r io.Reader) (lastHash string, eventCount int, firstChained int, err error) {
	eventCount, lastHash, firstChained, err = verifyChain(r)
	return lastHash, eventCount, firstChained, err
}

// verifyChain returns (eventCount, lastChainHash, firstChainedEventNumber, err).
// firstChainedEventNumber is 0 if no event in the log carried hash fields.
func verifyChain(r io.Reader) (int, string, int, error) {
	br := bufio.NewReader(r)

	var (
		prevHash     string
		eventNumber  int
		firstChained int
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
				return eventNumber, prevHash, firstChained, fmt.Errorf("audit: read input: %w", readErr)
			}
			continue
		}

		eventNumber++

		var e Event
		if err := json.Unmarshal(line, &e); err != nil {
			return eventNumber, prevHash, firstChained, &VerifyError{
				EventNumber: eventNumber,
				Reason:      fmt.Sprintf("invalid JSON: %s", err),
			}
		}

		// A log is chained as soon as ANY event carries hash fields. Events
		// without hash fields after that point are a tamper signal.
		if e.Hash != "" || e.PrevHash != "" {
			if firstChained == 0 {
				firstChained = eventNumber
			}
		} else if firstChained != 0 {
			return eventNumber, prevHash, firstChained, &VerifyError{
				EventNumber: eventNumber,
				Reason:      "event is missing hash fields in a chained log (possible truncation or tampering)",
			}
		} else {
			// Not chained at all yet; just count and move on.
			if readErr != nil {
				if errors.Is(readErr, io.EOF) {
					break
				}
				return eventNumber, prevHash, firstChained, fmt.Errorf("audit: read input: %w", readErr)
			}
			continue
		}

		// Re-compute the hash over the event with the Hash field zeroed,
		// exactly as the writer did.
		claimed := e.Hash
		e.Hash = ""
		recomputed, err := hashEvent(e)
		if err != nil {
			return eventNumber, prevHash, firstChained, fmt.Errorf("audit: event %d: recompute hash: %w", eventNumber, err)
		}
		if recomputed != claimed {
			return eventNumber, prevHash, firstChained, &VerifyError{
				EventNumber: eventNumber,
				Reason:      fmt.Sprintf("hash mismatch: claimed %q, recomputed %q", claimed, recomputed),
			}
		}
		if e.PrevHash != prevHash {
			return eventNumber, prevHash, firstChained, &VerifyError{
				EventNumber: eventNumber,
				Reason:      fmt.Sprintf("prev_hash mismatch: event records %q, previous event's hash was %q", e.PrevHash, prevHash),
			}
		}

		prevHash = claimed

		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				break
			}
			return eventNumber, prevHash, firstChained, fmt.Errorf("audit: read input: %w", readErr)
		}
	}

	return eventNumber, prevHash, firstChained, nil
}
