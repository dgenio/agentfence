package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBuildReportObservedEvidence(t *testing.T) {
	dir := t.TempDir()
	actionA := actionDigestPrefix + strings.Repeat("a", 64)
	actionB := actionDigestPrefix + strings.Repeat("b", 64)
	policy := policyDigestPrefix + strings.Repeat("c", 64)
	writeFixture(t, filepath.Join(dir, "decisions.json"), `[
  {"id":"1","tool":"filesystem.read","decision":"allow","reason":"rule"},
  {"id":"2","tool":"filesystem.write","decision":"deny","reason":"path denied"}
]`)
	writeFixture(t, filepath.Join(dir, "policy-tests.json"), `{"total":2,"passed":2,"failed":0,"cases":[]}`)
	writeFixture(t, filepath.Join(dir, "audit.jsonl"), fmt.Sprintf(
		"{\"action_digest\":%q,\"policy_digest\":%q}\n{\"action_digest\":%q,\"policy_digest\":%q}\n",
		actionA, policy, actionB, policy,
	))
	writeFixture(t, filepath.Join(dir, "audit-verification.json"), `{"chain":{"status":"ok","events":2}}`)

	report, err := buildReport(reportInput{
		DecisionsPath:          filepath.Join(dir, "decisions.json"),
		AuditPath:              filepath.Join(dir, "audit.jsonl"),
		AuditVerificationPath:  filepath.Join(dir, "audit-verification.json"),
		PolicyTestsPath:        filepath.Join(dir, "policy-tests.json"),
		PolicyValidationStatus: statusObserved,
		Context:                "dgenio/example@abc123",
	})
	if err != nil {
		t.Fatal(err)
	}
	if report.Summary.Decisions != 2 || report.Summary.Allow != 1 || report.Summary.Deny != 1 {
		t.Fatalf("unexpected decision summary: %+v", report.Summary)
	}
	if report.Summary.BoundAuditEvents != 2 || report.Summary.AuditEvents != 2 {
		t.Fatalf("unexpected binding coverage: %+v", report.Summary)
	}
	if !containsString(report.EvidenceIndex, "audit.jsonl") {
		t.Fatalf("local audit evidence missing from evidence index: %+v", report.EvidenceIndex)
	}
	for _, id := range []string{"policy_validation", "policy_fixtures", "mediated_call_decisions", "exact_action_policy_binding", "audit_chain_verification"} {
		if status := checkStatus(report, id); status != statusObserved {
			t.Fatalf("check %s status = %q, want observed", id, status)
		}
	}
	md := renderMarkdown(report)
	for _, required := range []string{
		"not a security certification or compliance attestation",
		"does not establish complete mediation",
		"does not claim to prevent prompt injection",
		"No missing, partial, or unevaluated evidence should be interpreted as safety.",
	} {
		if !strings.Contains(md, required) {
			t.Fatalf("markdown missing claim guardrail %q\n%s", required, md)
		}
	}
}

func TestBuildReportMissingBindingsArePartial(t *testing.T) {
	dir := t.TempDir()
	actionA := actionDigestPrefix + strings.Repeat("a", 64)
	actionB := actionDigestPrefix + strings.Repeat("b", 64)
	policy := policyDigestPrefix + strings.Repeat("c", 64)
	writeFixture(t, filepath.Join(dir, "decisions.json"), `[{"id":"1","tool":"x","decision":"allow","reason":"rule"}]`)
	writeFixture(t, filepath.Join(dir, "audit.jsonl"), fmt.Sprintf(
		"{\"action_digest\":%q,\"policy_digest\":%q}\n{\"action_digest\":%q}\n",
		actionA, policy, actionB,
	))

	report, err := buildReport(reportInput{
		DecisionsPath:          filepath.Join(dir, "decisions.json"),
		AuditPath:              filepath.Join(dir, "audit.jsonl"),
		PolicyValidationStatus: statusObserved,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := checkStatus(report, "exact_action_policy_binding"); got != statusPartial {
		t.Fatalf("binding status = %q, want partial", got)
	}
	check := findCheck(t, report, "exact_action_policy_binding")
	if !strings.Contains(check.Summary, "missing binding evidence is not treated as a pass") {
		t.Fatalf("partial binding summary is not fail-closed: %q", check.Summary)
	}
}

func TestBuildReportFailedEvidenceRemainsFailed(t *testing.T) {
	dir := t.TempDir()
	writeFixture(t, filepath.Join(dir, "decisions.json"), `[]`)
	writeFixture(t, filepath.Join(dir, "policy-tests.json"), `{"total":3,"passed":2,"failed":1,"cases":[]}`)
	writeFixture(t, filepath.Join(dir, "audit-verification.json"), `{"chain":{"status":"corrupt","events":3,"detail":"hash mismatch"}}`)

	report, err := buildReport(reportInput{
		DecisionsPath:          filepath.Join(dir, "decisions.json"),
		AuditVerificationPath:  filepath.Join(dir, "audit-verification.json"),
		PolicyTestsPath:        filepath.Join(dir, "policy-tests.json"),
		PolicyValidationStatus: statusFailed,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := checkStatus(report, "policy_validation"); got != statusFailed {
		t.Fatalf("policy validation = %q", got)
	}
	if got := checkStatus(report, "policy_fixtures"); got != statusFailed {
		t.Fatalf("policy fixtures = %q", got)
	}
	if got := checkStatus(report, "audit_chain_verification"); got != statusFailed {
		t.Fatalf("audit verification = %q", got)
	}
	if got := checkStatus(report, "mediated_call_decisions"); got != statusNotEvaluated {
		t.Fatalf("empty decisions = %q, want not_evaluated", got)
	}
}

func TestBuildReportRejectsMalformedAudit(t *testing.T) {
	dir := t.TempDir()
	writeFixture(t, filepath.Join(dir, "decisions.json"), `[]`)
	writeFixture(t, filepath.Join(dir, "audit.jsonl"), "{not-json}\n")

	_, err := buildReport(reportInput{
		DecisionsPath:          filepath.Join(dir, "decisions.json"),
		AuditPath:              filepath.Join(dir, "audit.jsonl"),
		PolicyValidationStatus: statusObserved,
	})
	if err == nil || !strings.Contains(err.Error(), "invalid JSONL") {
		t.Fatalf("err = %v, want invalid JSONL failure", err)
	}
}

func TestBuildReportRejectsMalformedBindingDigest(t *testing.T) {
	dir := t.TempDir()
	writeFixture(t, filepath.Join(dir, "decisions.json"), `[]`)
	writeFixture(t, filepath.Join(dir, "audit.jsonl"), `{"action_digest":"tool-action-json-v1:sha256:not-a-sha256","policy_digest":"resolved-policy-json-v1:sha256:also-bad"}`+"\n")

	_, err := buildReport(reportInput{
		DecisionsPath:          filepath.Join(dir, "decisions.json"),
		AuditPath:              filepath.Join(dir, "audit.jsonl"),
		PolicyValidationStatus: statusObserved,
	})
	if err == nil || !strings.Contains(err.Error(), "invalid action_digest") {
		t.Fatalf("err = %v, want malformed binding failure", err)
	}
}

func TestBuildReportRejectsNullEvidenceShapes(t *testing.T) {
	dir := t.TempDir()
	writeFixture(t, filepath.Join(dir, "decisions.json"), `null`)

	_, err := buildReport(reportInput{
		DecisionsPath:          filepath.Join(dir, "decisions.json"),
		PolicyValidationStatus: statusObserved,
	})
	if err == nil || !strings.Contains(err.Error(), "expected JSON array") {
		t.Fatalf("err = %v, want null decisions failure", err)
	}
}

func TestRenderMarkdownContextCannotInjectStructure(t *testing.T) {
	report := evidenceReport{
		SchemaVersion: reportSchemaVersion,
		Product:       "test",
		Context:       "owner/repo@sha`\n## forged heading",
		EvidenceIndex: []string{},
		Limitations:   []string{"limit"},
	}
	md := renderMarkdown(report)
	if strings.Contains(md, "\n## forged heading") {
		t.Fatalf("context escaped its code span:\n%s", md)
	}
	if !strings.Contains(md, "**Context:** `owner/repo@sha' ## forged heading`") {
		t.Fatalf("context was not rendered as one inert line:\n%s", md)
	}
}

func TestReportJSONUsesVersionedStatuses(t *testing.T) {
	report := evidenceReport{
		SchemaVersion: reportSchemaVersion,
		Product:       "test",
		Checks: []evidenceCheck{{
			ID:         "x",
			Status:     statusNotEvaluated,
			Summary:    "not evaluated",
			Limitation: "scope",
		}},
		EvidenceIndex: []string{},
		Limitations:   []string{"limit"},
	}
	data, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	if !strings.Contains(text, `"schema_version":"1"`) || !strings.Contains(text, `"status":"not_evaluated"`) {
		t.Fatalf("unexpected JSON contract: %s", text)
	}
}

func checkStatus(report evidenceReport, id string) string {
	for _, check := range report.Checks {
		if check.ID == id {
			return check.Status
		}
	}
	return ""
}

func findCheck(t *testing.T, report evidenceReport, id string) evidenceCheck {
	t.Helper()
	for _, check := range report.Checks {
		if check.ID == id {
			return check
		}
	}
	t.Fatalf("missing check %s", id)
	return evidenceCheck{}
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func writeFixture(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}
