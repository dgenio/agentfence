package main

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
