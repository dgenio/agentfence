package proxy

import (
	"bytes"
	"context"
	"testing"

	"github.com/dgenio/agentfence/internal/audit"
	"github.com/dgenio/agentfence/internal/engine"
	"github.com/dgenio/agentfence/internal/metrics"
	"github.com/dgenio/agentfence/internal/policy"
)

// TestProcessAgentLineRecordsMetrics verifies the stdio proxy records each
// decision (with tool and reason code) and evaluation latency into the metrics
// counters when Options.Metrics is set (#169, #101).
func TestProcessAgentLineRecordsMetrics(t *testing.T) {
	eng, err := engine.New(allowDenyAskPolicy(t))
	if err != nil {
		t.Fatalf("engine.New: %v", err)
	}
	counters := metrics.New()
	opts := Options{
		Engine:      eng,
		AuditWriter: audit.NewWriterOptions(&bytes.Buffer{}, audit.Options{SessionID: "test-session"}),
		Approver:    DenyAllApprover{},
		Metrics:     counters,
	}
	opts = applyDefaults(opts)
	r := newRelay(opts, eng.NewSession())

	sub := &bytes.Buffer{}
	agent := &bytes.Buffer{}

	// An allowed read and a denied delete.
	allow := helperRequest(t, `1`, "filesystem.read", `{"path":"README.md"}`)
	deny := helperRequest(t, `2`, "github.delete_repo", `{"repo":"x/y"}`)
	for _, line := range [][]byte{allow, deny} {
		if err := r.processAgentLine(context.Background(), line, sub, agent); err != nil {
			t.Fatalf("processAgentLine: %v", err)
		}
	}

	s := counters.Snapshot()
	if s.ByDecision["allow"] != 1 {
		t.Errorf("allow count = %d, want 1 (%v)", s.ByDecision["allow"], s.ByDecision)
	}
	if s.ByDecision["deny"] != 1 {
		t.Errorf("deny count = %d, want 1 (%v)", s.ByDecision["deny"], s.ByDecision)
	}
	if s.ByTool["filesystem.read"] != 1 {
		t.Errorf("ByTool[filesystem.read] = %d, want 1", s.ByTool["filesystem.read"])
	}
	if s.ByReasonCode[string(policy.ReasonCodeRuleMatch)] < 1 {
		t.Errorf("expected at least one rule_match reason code, got %v", s.ByReasonCode)
	}
	if s.EvalCount != 2 {
		t.Errorf("EvalCount = %d, want 2", s.EvalCount)
	}
}
