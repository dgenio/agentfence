package metrics

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/dgenio/agentfence/internal/policy"
)

func TestCountersRecordAndSnapshot(t *testing.T) {
	c := New()
	c.Record(policy.DecisionAllow, "fs.read", policy.ReasonCodeRuleMatch)
	c.Record(policy.DecisionAllow, "fs.read", policy.ReasonCodeRuleMatch)
	c.Record(policy.DecisionDeny, "github.delete_repo", policy.ReasonCodePathDenied)
	c.Record(policy.DecisionAsk, "shell.exec", policy.ReasonCodeTaintEscalated)
	c.Record(policy.DecisionDeny, "shell.exec", policy.ReasonCodeApprovalTimeout)

	s := c.Snapshot()

	if s.Total != 5 {
		t.Errorf("Total = %d, want 5", s.Total)
	}
	if s.ByDecision["allow"] != 2 || s.ByDecision["deny"] != 2 || s.ByDecision["ask"] != 1 {
		t.Errorf("ByDecision = %v, want allow=2 deny=2 ask=1", s.ByDecision)
	}
	if s.ByTool["fs.read"] != 2 {
		t.Errorf("ByTool[fs.read] = %d, want 2", s.ByTool["fs.read"])
	}
	if s.ByReasonCode["path_denied"] != 1 {
		t.Errorf("ByReasonCode[path_denied] = %d, want 1", s.ByReasonCode["path_denied"])
	}
	// Taint escalations are derived from the taint reason codes.
	if s.TaintEscalations != 1 {
		t.Errorf("TaintEscalations = %d, want 1", s.TaintEscalations)
	}
	// Approval outcomes are derived from the approval reason codes.
	if s.ApprovalOutcomes["approval_timeout"] != 1 {
		t.Errorf("ApprovalOutcomes[approval_timeout] = %d, want 1", s.ApprovalOutcomes["approval_timeout"])
	}
	if _, ok := s.ApprovalOutcomes["path_denied"]; ok {
		t.Errorf("ApprovalOutcomes must not contain non-approval codes: %v", s.ApprovalOutcomes)
	}
}

func TestCountersEmptyToolNotCounted(t *testing.T) {
	c := New()
	c.Record(policy.DecisionDeny, "", policy.ReasonCodeParseError)
	s := c.Snapshot()
	if len(s.ByTool) != 0 {
		t.Errorf("ByTool should be empty for an empty tool name, got %v", s.ByTool)
	}
	if s.ByReasonCode["parse_error"] != 1 {
		t.Errorf("parse_error not counted: %v", s.ByReasonCode)
	}
	if s.Total != 1 {
		t.Errorf("Total = %d, want 1", s.Total)
	}
}

func TestEvalLatencyMean(t *testing.T) {
	c := New()
	c.ObserveEvalLatency(10 * time.Millisecond)
	c.ObserveEvalLatency(30 * time.Millisecond)
	c.ObserveEvalLatency(-1) // ignored
	s := c.Snapshot()
	if s.EvalCount != 2 {
		t.Fatalf("EvalCount = %d, want 2", s.EvalCount)
	}
	if got := s.MeanEvalLatency(); got != 20*time.Millisecond {
		t.Errorf("MeanEvalLatency = %s, want 20ms", got)
	}
}

func TestMeanEvalLatencyZeroWhenNoSamples(t *testing.T) {
	if got := New().Snapshot().MeanEvalLatency(); got != 0 {
		t.Errorf("MeanEvalLatency with no samples = %s, want 0", got)
	}
}

func TestRecordError(t *testing.T) {
	c := New()
	c.RecordError("upstream")
	c.RecordError("upstream")
	c.RecordError("audit_write")
	c.RecordError("") // ignored
	s := c.Snapshot()
	if s.Errors["upstream"] != 2 || s.Errors["audit_write"] != 1 {
		t.Errorf("Errors = %v, want upstream=2 audit_write=1", s.Errors)
	}
	if _, ok := s.Errors[""]; ok {
		t.Errorf("empty error kind must be ignored")
	}
}

func TestWritePrometheusContainsExpectedSeries(t *testing.T) {
	c := New()
	c.Record(policy.DecisionDeny, "github.delete_repo", policy.ReasonCodePathDenied)
	c.Record(policy.DecisionAsk, "shell.exec", policy.ReasonCodeApprovalDenied)
	c.ObserveEvalLatency(5 * time.Millisecond)
	c.RecordError("upstream")

	var buf bytes.Buffer
	if err := c.Snapshot().WritePrometheus(&buf); err != nil {
		t.Fatalf("WritePrometheus error: %v", err)
	}
	out := buf.String()

	wants := []string{
		`agentfence_decisions_total{tool="github.delete_repo",decision="deny"} 1`,
		`agentfence_decisions_total{tool="shell.exec",decision="ask"} 1`,
		// The reason-code breakdown must be exported too (not only on the JSON
		// snapshot), matching the HELP text and the documented feature.
		`agentfence_reason_codes_total{code="path_denied"} 1`,
		`agentfence_reason_codes_total{code="approval_denied"} 1`,
		`agentfence_approval_outcomes_total{outcome="approval_denied"} 1`,
		`agentfence_eval_latency_seconds_count 1`,
		`agentfence_errors_total{kind="upstream"} 1`,
		"# TYPE agentfence_decisions_total counter",
	}
	for _, w := range wants {
		if !strings.Contains(out, w) {
			t.Errorf("Prometheus output missing %q\n---\n%s", w, out)
		}
	}
}

func TestFormatTextDeterministic(t *testing.T) {
	c := New()
	c.Record(policy.DecisionAllow, "b.tool", policy.ReasonCodeRuleMatch)
	c.Record(policy.DecisionAllow, "a.tool", policy.ReasonCodeRuleMatch)

	var a, b bytes.Buffer
	if err := c.Snapshot().FormatText(&a); err != nil {
		t.Fatalf("FormatText: %v", err)
	}
	if err := c.Snapshot().FormatText(&b); err != nil {
		t.Fatalf("FormatText: %v", err)
	}
	if a.String() != b.String() {
		t.Errorf("FormatText not deterministic:\n%s\n---\n%s", a.String(), b.String())
	}
	// Tools are listed in sorted order.
	out := a.String()
	if strings.Index(out, "a.tool") > strings.Index(out, "b.tool") {
		t.Errorf("tools not sorted in output:\n%s", out)
	}
}

func TestConcurrentRecord(t *testing.T) {
	c := New()
	const n = 100
	done := make(chan struct{})
	for i := 0; i < 4; i++ {
		go func() {
			for j := 0; j < n; j++ {
				c.Record(policy.DecisionAllow, "t", policy.ReasonCodeRuleMatch)
				c.ObserveEvalLatency(time.Microsecond)
			}
			done <- struct{}{}
		}()
	}
	for i := 0; i < 4; i++ {
		<-done
	}
	s := c.Snapshot()
	if s.Total != 4*n {
		t.Errorf("Total = %d, want %d", s.Total, 4*n)
	}
}
