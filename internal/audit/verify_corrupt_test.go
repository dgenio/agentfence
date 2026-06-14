package audit

import (
	"errors"
	"strings"
	"testing"

	"github.com/dgenio/agentfence/internal/policy"
)

// TestVerifyChainFlagsCorruptLineAsMalformed checks that an unparseable line is
// reported as a corrupt-input VerifyError (Malformed=true), distinct from an
// integrity break, so the CLI can tell "damaged file" apart from "tampering".
func TestVerifyChainFlagsCorruptLineAsMalformed(t *testing.T) {
	_, err := VerifyChain(strings.NewReader("{not valid json\n"))
	var ve *VerifyError
	if !errors.As(err, &ve) {
		t.Fatalf("VerifyChain error = %v, want *VerifyError", err)
	}
	if !ve.Malformed {
		t.Fatalf("VerifyError.Malformed = false, want true for an unparseable line")
	}
	if ve.EventNumber != 1 {
		t.Fatalf("EventNumber = %d, want 1", ve.EventNumber)
	}
}

// TestVerifyChainTamperIsNotMalformed checks that a genuine integrity break in
// a chained log is reported with Malformed=false, so it is not mistaken for a
// merely corrupt file.
func TestVerifyChainTamperIsNotMalformed(t *testing.T) {
	buf := &strings.Builder{}
	w := NewWriterOptions(buf, Options{TamperEvident: true, SessionID: "s"})
	for i := 0; i < 2; i++ {
		if err := w.Write(Event{CallID: "c", Tool: "t", Decision: policy.DecisionAllow, Reason: "ok"}); err != nil {
			t.Fatalf("Write: %v", err)
		}
	}
	// Corrupt the first event's claimed hash while keeping the line valid JSON:
	// recompute will mismatch, which is an integrity failure, not a parse error.
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	lines[0] = strings.Replace(lines[0], `"hash":"`, `"hash":"0`, 1)
	tampered := strings.Join(lines, "\n") + "\n"

	_, err := VerifyChain(strings.NewReader(tampered))
	var ve *VerifyError
	if !errors.As(err, &ve) {
		t.Fatalf("VerifyChain error = %v, want *VerifyError", err)
	}
	if ve.Malformed {
		t.Fatalf("VerifyError.Malformed = true, want false for an integrity break")
	}
}
