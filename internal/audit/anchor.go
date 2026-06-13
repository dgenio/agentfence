package audit

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"
)

// AnchorSchemaVersion is the schema_version stamped into every Anchor. Bump it
// when the anchor layout changes in a way external verifiers must distinguish.
const AnchorSchemaVersion = "1"

// Anchor is a compact, publishable commitment to the state of a tamper-evident
// audit log at a point in time. Committing it somewhere the operator does not
// control after the fact (a separate Git repo, a transparency log, a signed
// message) lets any third party detect silent whole-log deletion or truncation
// that the hash chain alone cannot: the chain proves internal consistency, but
// a deleted file leaves nothing to check. An anchor names a specific event that
// must still be present.
type Anchor struct {
	SchemaVersion string `json:"schema_version"`
	// SessionID is the session the anchored log belongs to, when the log is
	// single-session. Empty for mixed logs.
	SessionID string `json:"session_id,omitempty"`
	// EventCount is the number of non-blank events the log held when anchored.
	EventCount int `json:"event_count"`
	// LastSeq is the seq of the anchored (final) event.
	LastSeq uint64 `json:"last_seq"`
	// LastHash is the chain hash of the anchored event. Verification fails if
	// the log no longer contains an event with this seq and hash.
	LastHash string `json:"last_hash"`
	// Timestamp is when the anchor was produced (RFC3339Nano, UTC).
	Timestamp string `json:"timestamp"`
	// Signature is an optional base64 Ed25519 signature over the anchor's
	// canonical digest, authenticating who published it.
	Signature string `json:"signature,omitempty"`
}

// ErrAnchorTruncated is returned by VerifyAgainstAnchor when the log no longer
// reaches the anchored event — the signature of silent deletion or truncation.
var ErrAnchorTruncated = errors.New("audit: log does not reach the anchored event (possible truncation or deletion)")

// ComputeAnchor walks the chained audit log in r and returns an Anchor naming
// its final event. The log must be tamper-evident (fully chained); ComputeAnchor
// returns ErrNoChain / *PartialChainError exactly as VerifyChain does, since an
// anchor over an unverifiable log would be meaningless.
//
// When signer is non-nil the returned Anchor is signed.
func ComputeAnchor(r io.Reader, signer *Signer) (Anchor, error) {
	count, lastHash, firstChained, lastSeq, sessionID, err := scanAnchorState(r)
	if err != nil {
		return Anchor{}, err
	}
	switch {
	case count == 0:
		return Anchor{}, errors.New("audit: cannot anchor an empty log")
	case firstChained == 0:
		return Anchor{}, ErrNoChain
	case firstChained > 1:
		return Anchor{}, &PartialChainError{Total: count, ChainStartEvent: firstChained}
	}

	a := Anchor{
		SchemaVersion: AnchorSchemaVersion,
		SessionID:     sessionID,
		EventCount:    count,
		LastSeq:       lastSeq,
		LastHash:      lastHash,
		Timestamp:     time.Now().UTC().Format(time.RFC3339Nano),
	}
	if signer != nil {
		sig, err := signer.signAnchor(a)
		if err != nil {
			return Anchor{}, err
		}
		a.Signature = sig
	}
	return a, nil
}

// VerifyAgainstAnchor confirms the chained log in r still contains the event
// named by anchor — i.e. an event whose seq and chain hash match anchor.LastSeq
// and anchor.LastHash. The log may have grown since (more recent events are
// fine); it must not have shrunk past the anchored event.
//
// It first verifies the chain itself (so a tampered prefix is still caught),
// then looks for the anchored event. A log that ends before the anchored event
// returns ErrAnchorTruncated.
func VerifyAgainstAnchor(r io.Reader, anchor Anchor) error {
	br := bufio.NewReader(r)
	var (
		prevHash    string
		eventNumber int
		found       bool
	)
	for {
		line, readErr := br.ReadBytes('\n')
		line = bytes.TrimRight(line, "\r\n")
		if len(bytes.TrimSpace(line)) == 0 {
			if readErr != nil {
				if errors.Is(readErr, io.EOF) {
					break
				}
				return fmt.Errorf("audit: read input: %w", readErr)
			}
			continue
		}
		eventNumber++

		var e Event
		if err := json.Unmarshal(line, &e); err != nil {
			return &VerifyError{EventNumber: eventNumber, Reason: fmt.Sprintf("invalid JSON: %s", err)}
		}
		if e.Hash == "" && e.PrevHash == "" {
			return &VerifyError{EventNumber: eventNumber, Reason: "event is not chained; cannot verify against an anchor"}
		}

		claimed := e.Hash
		e.Hash = ""
		recomputed, err := hashEvent(e)
		if err != nil {
			return fmt.Errorf("audit: event %d: recompute hash: %w", eventNumber, err)
		}
		if recomputed != claimed {
			return &VerifyError{EventNumber: eventNumber, Reason: fmt.Sprintf("hash mismatch: claimed %q, recomputed %q", claimed, recomputed)}
		}
		if e.PrevHash != prevHash {
			return &VerifyError{EventNumber: eventNumber, Reason: fmt.Sprintf("prev_hash mismatch: event records %q, previous event's hash was %q", e.PrevHash, prevHash)}
		}
		prevHash = claimed

		if e.Sequence == anchor.LastSeq && claimed == anchor.LastHash {
			found = true
		}

		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				break
			}
			return fmt.Errorf("audit: read input: %w", readErr)
		}
	}
	if !found {
		return ErrAnchorTruncated
	}
	return nil
}

// signAnchor signs the anchor's canonical digest (the JSON encoding with
// Signature cleared).
func (s *Signer) signAnchor(a Anchor) (string, error) {
	digest, err := anchorDigest(a)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(ed25519.Sign(s.priv, digest[:])), nil
}

// VerifyAnchorSignature checks anchor.Signature against pub. Returns
// ErrNoSignature when the anchor is unsigned.
func VerifyAnchorSignature(anchor Anchor, pub ed25519.PublicKey) error {
	if anchor.Signature == "" {
		return ErrNoSignature
	}
	sig, err := base64.StdEncoding.DecodeString(anchor.Signature)
	if err != nil {
		return fmt.Errorf("audit: decode anchor signature: %w", err)
	}
	digest, err := anchorDigest(anchor)
	if err != nil {
		return err
	}
	if !ed25519.Verify(pub, digest[:], sig) {
		return errors.New("audit: anchor signature does not match")
	}
	return nil
}

func anchorDigest(a Anchor) ([32]byte, error) {
	a.Signature = ""
	b, err := json.Marshal(a)
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(b), nil
}

// scanAnchorState walks the log once, returning the event count, last chain
// hash, the 1-based position of the first chained event (0 if none), the last
// event's seq, and the single session ID (empty when the log mixes sessions).
func scanAnchorState(r io.Reader) (count int, lastHash string, firstChained int, lastSeq uint64, sessionID string, err error) {
	br := bufio.NewReader(r)
	multiSession := false
	for {
		line, readErr := br.ReadBytes('\n')
		line = bytes.TrimRight(line, "\r\n")
		if len(bytes.TrimSpace(line)) == 0 {
			if readErr != nil {
				if errors.Is(readErr, io.EOF) {
					break
				}
				return count, lastHash, firstChained, lastSeq, sessionID, fmt.Errorf("audit: read input: %w", readErr)
			}
			continue
		}
		count++
		var e Event
		if uerr := json.Unmarshal(line, &e); uerr != nil {
			return count, lastHash, firstChained, lastSeq, sessionID, &VerifyError{EventNumber: count, Reason: fmt.Sprintf("invalid JSON: %s", uerr)}
		}
		if (e.Hash != "" || e.PrevHash != "") && firstChained == 0 {
			firstChained = count
		}
		if e.Hash != "" {
			lastHash = e.Hash
		}
		lastSeq = e.Sequence
		if e.SessionID != "" {
			if sessionID == "" && !multiSession {
				sessionID = e.SessionID
			} else if sessionID != e.SessionID {
				multiSession = true
				sessionID = ""
			}
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				break
			}
			return count, lastHash, firstChained, lastSeq, sessionID, fmt.Errorf("audit: read input: %w", readErr)
		}
	}
	return count, lastHash, firstChained, lastSeq, sessionID, nil
}
