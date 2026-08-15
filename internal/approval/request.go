package approval

import (
	"encoding/json"
	"fmt"

	"github.com/dgenio/agentfence/internal/policy"
	"github.com/dgenio/agentfence/internal/redact"
)

const (
	// MaxArgumentsDisplayBytes bounds the deterministic redacted JSON rendered
	// in an approval prompt. Larger arguments are replaced by a safe metadata
	// summary; the exact action remains identified by ActionDigest and
	// BindingDigest.
	MaxArgumentsDisplayBytes = 2048
	// MaxLabelDisplayBytes bounds raw call/tool label bytes before terminal
	// rendering. Oversized labels are replaced by a deterministic safe summary.
	MaxLabelDisplayBytes = 256
)

// BoundRequest is the immutable approval-facing snapshot of one exact action
// under one exact effective policy. Its raw call is kept private so callers
// cannot mutate the approval evidence through an exported map.
type BoundRequest struct {
	call             policy.ToolCall
	actionDigest     string
	policyDigest     string
	bindingDigest    string
	callDisplay      string
	toolDisplay      string
	argumentsDisplay string
}

// NewBoundRequest validates that call matches actionDigest, constructs the
// action/policy approval binding, and prepares a deterministic size-bounded
// redacted display. Display construction is fail-closed: it never falls back to
// raw arguments on redaction or serialization failure.
func NewBoundRequest(call policy.ToolCall, actionDigest, policyDigest string, redactor *redact.Redactor) (BoundRequest, error) {
	if redactor == nil {
		return BoundRequest{}, fmt.Errorf("approval request: redactor is required")
	}

	snapshot, err := policy.SnapshotToolCall(call)
	if err != nil {
		return BoundRequest{}, fmt.Errorf("approval request: snapshot call: %w", err)
	}
	computedAction, err := policy.ToolActionDigest(snapshot)
	if err != nil {
		return BoundRequest{}, fmt.Errorf("approval request: action digest: %w", err)
	}
	if computedAction != actionDigest {
		return BoundRequest{}, fmt.Errorf("approval request: action digest does not match exact call snapshot")
	}

	binding, err := NewBinding(actionDigest, policyDigest)
	if err != nil {
		return BoundRequest{}, err
	}
	bindingDigest, err := binding.Digest()
	if err != nil {
		return BoundRequest{}, err
	}

	redacted := redactor.RedactArgumentsConfigured(snapshot.Arguments)
	encoded, err := json.Marshal(redacted)
	if err != nil {
		return BoundRequest{}, fmt.Errorf("approval request: serialize redacted arguments: %w", err)
	}
	display := string(encoded)
	if len(encoded) > MaxArgumentsDisplayBytes {
		summary, err := json.Marshal(map[string]interface{}{
			"omitted":        true,
			"reason":         "redacted approval display exceeds size limit",
			"redacted_bytes": len(encoded),
		})
		if err != nil {
			return BoundRequest{}, fmt.Errorf("approval request: serialize bounded display: %w", err)
		}
		display = string(summary)
	}

	callDisplay, err := boundedLabelDisplay("call id", snapshot.ID)
	if err != nil {
		return BoundRequest{}, err
	}
	toolDisplay, err := boundedLabelDisplay("tool name", snapshot.Tool)
	if err != nil {
		return BoundRequest{}, err
	}

	return BoundRequest{
		call:             snapshot,
		actionDigest:     actionDigest,
		policyDigest:     policyDigest,
		bindingDigest:    bindingDigest,
		callDisplay:      callDisplay,
		toolDisplay:      toolDisplay,
		argumentsDisplay: display,
	}, nil
}

// CallSnapshot returns a deep copy of the exact call this request binds. A
// caller may mutate the returned value without changing the approval request.
func (r BoundRequest) CallSnapshot() (policy.ToolCall, error) {
	return policy.SnapshotToolCall(r.call)
}

// CallID returns the exact correlation ID. It is not part of the semantic
// action digest. Prompt uses a separately escaped/bounded representation.
func (r BoundRequest) CallID() string { return r.call.ID }

// Tool returns the exact tool name bound by this request. Prompt uses a
// separately escaped/bounded representation.
func (r BoundRequest) Tool() string { return r.call.Tool }

// ActionDigest returns the exact tool-action identity.
func (r BoundRequest) ActionDigest() string { return r.actionDigest }

// PolicyDigest returns the resolved effective-policy identity.
func (r BoundRequest) PolicyDigest() string { return r.policyDigest }

// BindingDigest returns the approval-binding identity over action + policy.
func (r BoundRequest) BindingDigest() string { return r.bindingDigest }

// ArgumentsDisplay returns deterministic redacted JSON or a deterministic safe
// summary when the redacted representation exceeds MaxArgumentsDisplayBytes.
func (r BoundRequest) ArgumentsDisplay() string { return r.argumentsDisplay }

// Prompt renders the bounded operator-facing approval text. Call/tool labels
// are JSON-escaped so control characters cannot inject terminal lines, and
// oversized labels are replaced by safe summaries. The prompt contains no raw
// argument fallback; exact identity is carried by the full versioned digests
// even when a human display component is omitted for size.
func (r BoundRequest) Prompt() string {
	return fmt.Sprintf(
		"AgentFence approval\n  call:    %s\n  tool:    %s\n  args:    %s\n  action:  %s\n  policy:  %s\n  binding: %s\napprove? (y/N): ",
		r.callDisplay, r.toolDisplay, r.ArgumentsDisplay(), r.ActionDigest(), r.PolicyDigest(), r.BindingDigest(),
	)
}

func boundedLabelDisplay(kind, value string) (string, error) {
	if len([]byte(value)) <= MaxLabelDisplayBytes {
		encoded, err := json.Marshal(value)
		if err != nil {
			return "", fmt.Errorf("approval request: serialize %s: %w", kind, err)
		}
		return string(encoded), nil
	}
	summary, err := json.Marshal(fmt.Sprintf("<omitted: %s exceeds %d-byte display limit; bytes=%d>", kind, MaxLabelDisplayBytes, len([]byte(value))))
	if err != nil {
		return "", fmt.Errorf("approval request: serialize bounded %s: %w", kind, err)
	}
	return string(summary), nil
}
