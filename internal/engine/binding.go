package engine

import (
	"fmt"

	"github.com/dgenio/agentfence/internal/audit"
	"github.com/dgenio/agentfence/internal/policy"
)

// EvaluateBound evaluates a deep snapshot of a tool call only after exact
// action and effective-policy identities have been computed successfully.
//
// Snapshotting prevents the digest and the evaluator from observing different
// map-backed inputs if a caller mutates its original ToolCall after handing it
// to the engine. Binding failures deny before ordinary policy evaluation so an
// action cannot inherit authority without the evidence needed to reproduce that
// decision.
//
// The existing Evaluate method is intentionally unchanged in this slice; proxy
// and CLI call sites migrate to this fail-closed path separately.
func (e *Engine) EvaluateBound(call policy.ToolCall) (policy.EvaluationResult, audit.Event) {
	snapshot, err := policy.SnapshotToolCall(call)
	if err != nil {
		return e.bindingFailure(call, policy.ReasonCodeActionBindingFailed, "exact action binding failed", "", err)
	}
	return e.evaluateBoundSnapshot(snapshot)
}

func (e *Engine) evaluateBoundSnapshot(call policy.ToolCall) (policy.EvaluationResult, audit.Event) {
	actionDigest, err := policy.ToolActionDigest(call)
	if err != nil {
		return e.bindingFailure(call, policy.ReasonCodeActionBindingFailed, "exact action binding failed", "", err)
	}

	policySnapshot, err := policy.SnapshotResolvedPolicy(e.policy)
	if err != nil {
		return e.bindingFailure(call, policy.ReasonCodePolicyBindingFailed, "effective policy binding failed", actionDigest, err)
	}
	policyDigest, err := policy.EffectivePolicyDigest(policySnapshot)
	if err != nil {
		return e.bindingFailure(call, policy.ReasonCodePolicyBindingFailed, "effective policy binding failed", actionDigest, err)
	}

	// Evaluate through an engine built from the same deep policy snapshot whose
	// digest is emitted below. The decision therefore cannot observe a later
	// mutation of e.policy while claiming the earlier policy identity.
	snapshotEngine, err := New(policySnapshot)
	if err != nil {
		return e.bindingFailure(call, policy.ReasonCodePolicyBindingFailed, "effective policy binding failed", actionDigest, err)
	}
	result, event := snapshotEngine.Evaluate(call)
	event.ActionDigest = actionDigest
	event.PolicyDigest = policyDigest
	return result, event
}

// EvaluateBound is the session-aware counterpart to Engine.EvaluateBound. It
// snapshots once, preserves exact decision bindings, and applies the same taint
// escalation as Session.Evaluate against that exact action snapshot.
func (s *Session) EvaluateBound(call policy.ToolCall) (policy.EvaluationResult, audit.Event) {
	snapshot, err := policy.SnapshotToolCall(call)
	if err != nil {
		return s.eng.bindingFailure(call, policy.ReasonCodeActionBindingFailed, "exact action binding failed", "", err)
	}
	res, event := s.eng.evaluateBoundSnapshot(snapshot)
	if res.ReasonCode == policy.ReasonCodeActionBindingFailed || res.ReasonCode == policy.ReasonCodePolicyBindingFailed {
		return res, event
	}
	if s.tracker == nil {
		return res, event
	}
	if hit, ok := s.tracker.Check(snapshot.Arguments); ok {
		res, event = applyTaintEscalation(res, event, hit, s.mode)
	}
	return res, event
}

func (e *Engine) bindingFailure(call policy.ToolCall, code policy.ReasonCode, prefix, actionDigest string, err error) (policy.EvaluationResult, audit.Event) {
	result := policy.EvaluationResult{
		Decision:   policy.DecisionDeny,
		Reason:     fmt.Sprintf("%s: %v", prefix, err),
		ReasonCode: code,
	}
	// Do not copy arguments into a binding-failure event: the failure means the
	// request cannot yet be represented by the exact action contract. Recording
	// the raw/partially interpreted map here would invite consumers to treat it
	// as equivalent evidence.
	event := audit.NewEvent(call, result, nil, false)
	event.ActionDigest = actionDigest
	return result, event
}
