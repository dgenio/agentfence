package main

import (
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
)

func buildReport(in reportInput) (evidenceReport, error) {
	if !validPolicyValidationStatus(in.PolicyValidationStatus) {
		return evidenceReport{}, fmt.Errorf("invalid --policy-validation-status %q", in.PolicyValidationStatus)
	}

	decisions, err := readDecisions(in.DecisionsPath)
	if err != nil {
		return evidenceReport{}, err
	}

	summary := reportSummary{Decisions: len(decisions)}
	for _, decision := range decisions {
		switch decision.Decision {
		case "allow":
			summary.Allow++
		case "deny":
			summary.Deny++
		case "ask":
			summary.Ask++
		default:
			return evidenceReport{}, fmt.Errorf("decisions: unsupported decision %q for call %q", decision.Decision, decision.ID)
		}
	}

	checks := []evidenceCheck{policyValidationCheck(in.PolicyValidationStatus)}
	evidenceIndex := []string{filepath.Base(in.DecisionsPath)}
	if in.PolicyValidationStatus != statusNotEvaluated {
		evidenceIndex = append(evidenceIndex, "policy-validation.txt")
	}

	policyCheck, testSummary, err := policyTestsCheck(in.PolicyTestsPath)
	if err != nil {
		return evidenceReport{}, err
	}
	checks = append(checks, policyCheck)
	summary.PolicyTests = testSummary.Total
	summary.PolicyTestsPassed = testSummary.Passed
	summary.PolicyTestsFailed = testSummary.Failed
	if in.PolicyTestsPath != "" {
		evidenceIndex = append(evidenceIndex, filepath.Base(in.PolicyTestsPath))
	}

	checks = append(checks, mediatedDecisionsCheck(decisions, in.DecisionsPath))

	auditCount, boundCount, err := auditBindingCounts(in.AuditPath)
	if err != nil {
		return evidenceReport{}, err
	}
	summary.AuditEvents = auditCount
	summary.BoundAuditEvents = boundCount
	checks = append(checks, bindingCoverageCheck(auditCount, boundCount, in.AuditPath))

	verifyCheck, err := auditVerificationCheck(in.AuditVerificationPath)
	if err != nil {
		return evidenceReport{}, err
	}
	checks = append(checks, verifyCheck)
	if in.AuditVerificationPath != "" {
		evidenceIndex = append(evidenceIndex, filepath.Base(in.AuditVerificationPath))
	}

	return evidenceReport{
		SchemaVersion: reportSchemaVersion,
		Product:       "VeriCordon authorization evidence bundle (AgentFence preview)",
		Context:       strings.TrimSpace(in.Context),
		Summary:       summary,
		Checks:        checks,
		EvidenceIndex: uniqueSorted(evidenceIndex),
		Limitations: []string{
			"Evidence covers only the supplied calls evaluated through the AgentFence/VeriCordon boundary; it does not establish complete mediation of the surrounding agent or host.",
			"This report is not a sandbox result and does not claim to prevent prompt injection or make the model trustworthy.",
			"An allowed mediated call does not prove what the downstream tool or external service did after forwarding.",
			"This report is not a security certification, compliance attestation, or proof of conformance with AIUC-1 or another external standard.",
			"Policy validation and passing fixtures show that the supplied policy parses and behaves as tested; they do not prove the policy is sufficient for the operator's environment.",
			"Raw audit events can contain argument values unless configured redaction matches them. Binding coverage is derived locally from that raw input; the safe CI artifact omits raw audit by default, so independent recomputation requires explicit access to the local/raw audit evidence.",
		},
	}, nil
}

func validPolicyValidationStatus(status string) bool {
	switch status {
	case statusObserved, statusFailed, statusNotEvaluated:
		return true
	default:
		return false
	}
}

func policyValidationCheck(status string) evidenceCheck {
	check := evidenceCheck{
		ID:         "policy_validation",
		Status:     status,
		Evidence:   []string{"policy-validation.txt"},
		Limitation: "Validation establishes that the supplied policy is well-formed under the current parser; it does not establish that the policy is sufficient for the deployment.",
	}
	switch status {
	case statusObserved:
		check.Summary = "The supplied policy validation command completed successfully."
	case statusFailed:
		check.Summary = "The supplied policy did not validate; downstream evidence must not be interpreted as an enforcement pass."
	default:
		check.Summary = "Policy validation was not evaluated by this report input."
		check.Evidence = nil
	}
	return check
}

func policyTestsCheck(path string) (evidenceCheck, policyTestReport, error) {
	check := evidenceCheck{
		ID:         "policy_fixtures",
		Status:     statusNotEvaluated,
		Summary:    "No policy fixture report was supplied.",
		Limitation: "Passing fixtures demonstrate only the cases encoded in the supplied test file; they do not establish complete policy correctness.",
	}
	if path == "" {
		return check, policyTestReport{}, nil
	}
	var tests policyTestReport
	if err := readJSON(path, &tests); err != nil {
		return evidenceCheck{}, policyTestReport{}, fmt.Errorf("policy tests: %w", err)
	}
	if tests.Total < 0 || tests.Passed < 0 || tests.Failed < 0 || tests.Passed+tests.Failed != tests.Total {
		return evidenceCheck{}, policyTestReport{}, errors.New("policy tests: inconsistent totals")
	}
	check.Evidence = []string{filepath.Base(path)}
	if tests.Failed > 0 {
		check.Status = statusFailed
		check.Summary = fmt.Sprintf("%d of %d supplied policy fixtures failed.", tests.Failed, tests.Total)
	} else if tests.Total == 0 {
		check.Status = statusNotEvaluated
		check.Summary = "The supplied policy fixture report contained no test cases."
	} else {
		check.Status = statusObserved
		check.Summary = fmt.Sprintf("All %d supplied policy fixtures passed.", tests.Total)
	}
	return check, tests, nil
}

func mediatedDecisionsCheck(decisions []decisionSummary, path string) evidenceCheck {
	check := evidenceCheck{
		ID:         "mediated_call_decisions",
		Status:     statusNotEvaluated,
		Summary:    "No mediated call decisions were supplied.",
		Evidence:   []string{filepath.Base(path)},
		Limitation: "These decisions cover only the calls supplied to the evaluator; they do not prove that every capability or execution path in the surrounding system was mediated.",
	}
	if len(decisions) > 0 {
		check.Status = statusObserved
		check.Summary = fmt.Sprintf("%d supplied mediated call decisions were evaluated and recorded.", len(decisions))
	}
	return check
}

func bindingCoverageCheck(events, bound int, path string) evidenceCheck {
	check := evidenceCheck{
		ID:         "exact_action_policy_binding",
		Status:     statusNotEvaluated,
		Summary:    "No audit events were supplied for action/policy binding coverage.",
		Limitation: "Binding coverage is an observation about the supplied audit events only. It does not establish upstream identity, complete mediation, or downstream execution effects. Raw audit is local evidence and is not included in the safe CI artifact unless explicitly requested.",
	}
	if path == "" || events == 0 {
		return check
	}
	check.Evidence = []string{filepath.Base(path)}
	if bound == events {
		check.Status = statusObserved
		check.Summary = fmt.Sprintf("All %d supplied audit events carry both action_digest and policy_digest.", events)
		return check
	}
	check.Status = statusPartial
	check.Summary = fmt.Sprintf("%d of %d supplied audit events carry both action_digest and policy_digest; missing binding evidence is not treated as a pass.", bound, events)
	return check
}

func auditVerificationCheck(path string) (evidenceCheck, error) {
	check := evidenceCheck{
		ID:         "audit_chain_verification",
		Status:     statusNotEvaluated,
		Summary:    "No audit verification result was supplied.",
		Limitation: "A valid local hash chain detects covered record mutation/reordering under the verifier's contract; it does not prove complete collection, external anchoring, or what happened after an allowed call.",
	}
	if path == "" {
		return check, nil
	}
	var verification auditVerifyReport
	if err := readJSON(path, &verification); err != nil {
		return evidenceCheck{}, fmt.Errorf("audit verification: %w", err)
	}
	check.Evidence = []string{filepath.Base(path)}
	if verification.Chain.Status == "ok" {
		check.Status = statusObserved
		check.Summary = fmt.Sprintf("The supplied audit verification reports an intact hash chain across %d events.", verification.Chain.Events)
	} else {
		check.Status = statusFailed
		check.Summary = fmt.Sprintf("Audit chain verification status is %q; integrity is not treated as established.", verification.Chain.Status)
	}
	return check, nil
}

func uniqueSorted(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if value != "" {
			seen[value] = struct{}{}
		}
	}
	out := make([]string, 0, len(seen))
	for value := range seen {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}
