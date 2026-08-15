package engine

import (
	"fmt"

	"github.com/dgenio/agentfence/internal/audit"
	"github.com/dgenio/agentfence/internal/policy"
)

// EvaluateBound evaluates a tool call only after exact action and effective-
// policy identities have been computed successfully.
//
// Binding failures deny before ordinary policy evaluation so an action cannot
// inherit authority without the evidence needed to reproduce that decision.
// The existing Evaluate method is intentionally unchanged in this slice; proxy
// and CLI call sites migrate to this fail-closed path separately.
func (e *Engine) EvaluateBound(call policy.ToolCall) (policy.EvaluationResult, audit.Event) {
	actionDigest, err := policy.ToolActionDigest(call)
	if err != nil {
		return e.bindingFailure(call, policy.ReasonCodeActionBindingFailed, "exact action binding failed", "", err)
	}

	policyDigest, err := policy.EffectivePolicyDigest(e.policy)
	if err != nil {
		return e.bindingFailure(call, policy.ReasonCodePolicyBindingFailed, "effective policy binding failed", actionDigest, err)
	}

	result, event := e.Evaluate(call)
	event.ActionDigest = actionDigest
	event.PolicyDigest = policyDigest
	return result, event
}

// EvaluateBound is the session-aware counterpart to Engine.EvaluateBound. It
// preserves exact decision bindings while applying the same taint escalation as
// Session.Evaluate after the bound base decision is available.
func (s *Session) EvaluateBound(call policy.ToolCall) (policy.EvaluationResult, audit.Event) {
	res, event := s.eng.EvaluateBound(call)
	if res.ReasonCode == policy.ReasonCodeActionBindingFailed || res.ReasonCode == policy.ReasonCodePolicyBindingFailed {
		return res, event
	}
	if s.tracker == nil {
		return res, event
	}
	if hit, ok := s.tracker.Check(call.Arguments); ok {
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
