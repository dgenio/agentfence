package approval

import (
	"fmt"

	"github.com/dgenio/agentfence/internal/policy"
)

// Validate re-checks the immutable approval request invariants before an
// approver displays or acts on it. The zero value and any internally-corrupted
// value fail closed without showing a prompt.
func (r BoundRequest) Validate() error {
	if r.call.ID == "" {
		return fmt.Errorf("approval request: call id is required")
	}
	if r.call.Tool == "" {
		return fmt.Errorf("approval request: tool name is required")
	}
	if r.argumentsDisplay == "" || r.callDisplay == "" || r.toolDisplay == "" {
		return fmt.Errorf("approval request: display evidence is incomplete")
	}

	snapshot, err := policy.SnapshotToolCall(r.call)
	if err != nil {
		return fmt.Errorf("approval request: snapshot call: %w", err)
	}
	actionDigest, err := policy.ToolActionDigest(snapshot)
	if err != nil {
		return fmt.Errorf("approval request: action digest: %w", err)
	}
	if actionDigest != r.actionDigest {
		return fmt.Errorf("approval request: action digest does not match exact call snapshot")
	}

	binding, err := NewBinding(r.actionDigest, r.policyDigest)
	if err != nil {
		return err
	}
	bindingDigest, err := binding.Digest()
	if err != nil {
		return err
	}
	if bindingDigest != r.bindingDigest {
		return fmt.Errorf("approval request: binding digest does not match action/policy evidence")
	}
	return nil
}
