package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const reportSchemaVersion = "1"

const (
	statusObserved     = "observed"
	statusPartial      = "partial"
	statusNotEvaluated = "not_evaluated"
	statusFailed       = "failed"
)

type decisionSummary struct {
	ID       string `json:"id"`
	Tool     string `json:"tool"`
	Decision string `json:"decision"`
	Reason   string `json:"reason"`
}

type policyTestReport struct {
	Total  int `json:"total"`
	Passed int `json:"passed"`
	Failed int `json:"failed"`
}

type auditVerifyReport struct {
	Chain struct {
		Status string `json:"status"`
		Events int    `json:"events"`
		Detail string `json:"detail,omitempty"`
	} `json:"chain"`
}

type auditEvent struct {
	ActionDigest string `json:"action_digest,omitempty"`
	PolicyDigest string `json:"policy_digest,omitempty"`
}

type evidenceCheck struct {
	ID         string   `json:"id"`
	Status     string   `json:"status"`
	Summary    string   `json:"summary"`
	Evidence   []string `json:"evidence,omitempty"`
	Limitation string   `json:"limitation"`
}

type reportSummary struct {
	Decisions         int `json:"decisions"`
	Allow             int `json:"allow"`
	Deny              int `json:"deny"`
	Ask               int `json:"ask"`
	AuditEvents       int `json:"audit_events"`
	BoundAuditEvents  int `json:"bound_audit_events"`
	PolicyTests       int `json:"policy_tests"`
	PolicyTestsPassed int `json:"policy_tests_passed"`
	PolicyTestsFailed int `json:"policy_tests_failed"`
}

type evidenceReport struct {
	SchemaVersion string          `json:"schema_version"`
	Product       string          `json:"product"`
	Context       string          `json:"context,omitempty"`
	Summary       reportSummary   `json:"summary"`
	Checks        []evidenceCheck `json:"checks"`
	EvidenceIndex []string        `json:"evidence_index"`
	Limitations   []string        `json:"limitations"`
}

type reportInput struct {
	DecisionsPath          string
	AuditPath              string
	AuditVerificationPath  string
	PolicyTestsPath        string
	PolicyValidationStatus string
	Context                string
}

func main() {
	var in reportInput
	var outputJSON, outputMarkdown string

	flag.StringVar(&in.DecisionsPath, "decisions", "", "Path to AgentFence check --output json decisions")
	flag.StringVar(&in.AuditPath, "audit", "", "Optional path to AgentFence audit JSONL used only for aggregate binding coverage")
	flag.StringVar(&in.AuditVerificationPath, "audit-verification", "", "Optional path to agentfence audit verify --output json")
	flag.StringVar(&in.PolicyTestsPath, "policy-tests", "", "Optional path to agentfence policy test --output json")
	flag.StringVar(&in.PolicyValidationStatus, "policy-validation-status", statusNotEvaluated, "Policy validation status: observed, failed, or not_evaluated")
	flag.StringVar(&in.Context, "context", "", "Optional source context such as owner/repo@commit")
	flag.StringVar(&outputJSON, "output-json", "", "Path to write the versioned machine-readable report")
	flag.StringVar(&outputMarkdown, "output-md", "", "Path to write the human-readable Markdown report")
	flag.Parse()

	if in.DecisionsPath == "" {
		fatal(errors.New("--decisions is required"))
	}
	if outputJSON == "" || outputMarkdown == "" {
		fatal(errors.New("--output-json and --output-md are required"))
	}

	report, err := buildReport(in)
	if err != nil {
		fatal(err)
	}
	if err := writeJSON(outputJSON, report); err != nil {
		fatal(err)
	}
	if err := os.WriteFile(outputMarkdown, []byte(renderMarkdown(report)), 0o644); err != nil {
		fatal(fmt.Errorf("write markdown report: %w", err))
	}
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "evidence-report:", err)
	os.Exit(1)
}

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
			"Raw audit events can contain argument values unless configured redaction matches them; this report records aggregate binding coverage and should not be treated as evidence that the raw audit log is secret-safe.",
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
		Limitation: "Binding coverage is an observation about the supplied audit events only. It does not establish upstream identity, complete mediation, or downstream execution effects.",
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

func readDecisions(path string) ([]decisionSummary, error) {
	var decisions []decisionSummary
	if err := readJSON(path, &decisions); err != nil {
		return nil, fmt.Errorf("decisions: %w", err)
	}
	return decisions, nil
}

func readJSON(path string, dst any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(data, dst); err != nil {
		return err
	}
	return nil
}

func auditBindingCounts(path string) (int, int, error) {
	if path == "" {
		return 0, 0, nil
	}
	file, err := os.Open(path)
	if err != nil {
		return 0, 0, fmt.Errorf("audit: %w", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)
	total := 0
	bound := 0
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var event auditEvent
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			return 0, 0, fmt.Errorf("audit: invalid JSONL event %d: %w", total+1, err)
		}
		total++
		if event.ActionDigest != "" && event.PolicyDigest != "" {
			bound++
		}
	}
	if err := scanner.Err(); err != nil {
		return 0, 0, fmt.Errorf("audit: %w", err)
	}
	return total, bound, nil
}

func writeJSON(path string, report evidenceReport) error {
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal report: %w", err)
	}
	data = append(data, '\n')
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("write json report: %w", err)
	}
	return nil
}

func renderMarkdown(report evidenceReport) string {
	var b strings.Builder
	b.WriteString("# VeriCordon authorization evidence report\n\n")
	b.WriteString("> Preview generated from AgentFence local evidence. This is scoped engineering evidence, not a security certification or compliance attestation.\n\n")
	if report.Context != "" {
		fmt.Fprintf(&b, "**Context:** `%s`\n\n", markdownCode(report.Context))
	}
	b.WriteString("## Evidence summary\n\n")
	fmt.Fprintf(&b, "- Mediated decisions supplied: **%d** (allow %d · deny %d · ask %d)\n", report.Summary.Decisions, report.Summary.Allow, report.Summary.Deny, report.Summary.Ask)
	fmt.Fprintf(&b, "- Audit events inspected for binding evidence: **%d**; both action + policy digests present: **%d**\n", report.Summary.AuditEvents, report.Summary.BoundAuditEvents)
	if report.Summary.PolicyTests > 0 {
		fmt.Fprintf(&b, "- Policy fixtures: **%d** (passed %d · failed %d)\n", report.Summary.PolicyTests, report.Summary.PolicyTestsPassed, report.Summary.PolicyTestsFailed)
	}

	b.WriteString("\n## Evidence checks\n\n")
	b.WriteString("| Check | Status | What the supplied evidence says | Boundary |\n")
	b.WriteString("| --- | --- | --- | --- |\n")
	for _, check := range report.Checks {
		fmt.Fprintf(&b, "| `%s` | **%s** | %s | %s |\n", markdownCell(check.ID), markdownCell(check.Status), markdownCell(check.Summary), markdownCell(check.Limitation))
	}

	b.WriteString("\n## Evidence index\n\n")
	for _, name := range report.EvidenceIndex {
		fmt.Fprintf(&b, "- `%s`\n", markdownCode(name))
	}

	b.WriteString("\n## Limitations / non-claims\n\n")
	for _, limitation := range report.Limitations {
		fmt.Fprintf(&b, "- %s\n", limitation)
	}
	b.WriteString("\nNo missing, partial, or unevaluated evidence should be interpreted as safety.\n")
	return b.String()
}

func markdownCell(s string) string {
	s = strings.ReplaceAll(s, "|", "\\|")
	s = strings.ReplaceAll(s, "\n", " ")
	return s
}

func markdownCode(s string) string {
	return strings.ReplaceAll(s, "`", "'")
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
	for i := 0; i < len(out); i++ {
		for j := i + 1; j < len(out); j++ {
			if out[j] < out[i] {
				out[i], out[j] = out[j], out[i]
			}
		}
	}
	return out
}
