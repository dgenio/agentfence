package audit

import (
	"bytes"
	"strings"
	"testing"

	"github.com/dgenio/agentfence/internal/policy"
)

// TestSummarizeGroupsByReasonCode verifies that Summarize aggregates the stable
// reason_code field (#136) and that the text report surfaces it.
func TestSummarizeGroupsByReasonCode(t *testing.T) {
	events := []Event{
		{Tool: "fs.read", Decision: policy.DecisionAllow, Reason: "ok", ReasonCode: policy.ReasonCodeRuleMatch},
		{Tool: "fs.read", Decision: policy.DecisionDeny, Reason: "path x denied by pattern y", ReasonCode: policy.ReasonCodePathDenied},
		{Tool: "fs.write", Decision: policy.DecisionDeny, Reason: "path a denied by pattern b", ReasonCode: policy.ReasonCodePathDenied},
		// An event without a reason code (pre-taxonomy) must not be counted.
		{Tool: "old.tool", Decision: policy.DecisionAllow, Reason: "legacy"},
	}
	log := writeLog(t, events)

	s, err := Summarize(bytes.NewReader(log), 10)
	if err != nil {
		t.Fatalf("Summarize() error = %v", err)
	}

	if s.ByReasonCode["path_denied"] != 2 {
		t.Errorf("ByReasonCode[path_denied] = %d, want 2", s.ByReasonCode["path_denied"])
	}
	if s.ByReasonCode["rule_match"] != 1 {
		t.Errorf("ByReasonCode[rule_match] = %d, want 1", s.ByReasonCode["rule_match"])
	}
	// The pre-taxonomy event (no reason_code) is excluded from the grouping but
	// still counted in Total.
	if len(s.ByReasonCode) != 2 {
		t.Errorf("ByReasonCode has %d keys, want 2: %v", len(s.ByReasonCode), s.ByReasonCode)
	}
	if s.Total != 4 {
		t.Errorf("Total = %d, want 4", s.Total)
	}

	var buf bytes.Buffer
	if err := s.FormatText(&buf); err != nil {
		t.Fatalf("FormatText() error = %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "By reason code:") {
		t.Errorf("text report missing reason-code section:\n%s", out)
	}
	if !strings.Contains(out, "path_denied") {
		t.Errorf("text report missing path_denied:\n%s", out)
	}
}
