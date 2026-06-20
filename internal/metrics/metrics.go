// Package metrics provides lightweight, dependency-free decision counters for
// the AgentFence CLI and proxies.
//
// Counters is the single in-process aggregation point: the check command and
// both proxies record each evaluated decision into it, then render it as a
// human-readable summary, stable JSON (the zero-dependency baseline of #169),
// or Prometheus text-exposition output for the proxies' opt-in /metrics
// endpoint (#101). Keeping one Counters type means the on-exit CLI summary and
// the scrapable proxy endpoint always report the same shape.
//
// Counters is safe for concurrent use: the HTTP proxy records decisions on
// request goroutines while a scrape reads a Snapshot on another.
package metrics

import (
	"fmt"
	"io"
	"sort"
	"sync"
	"time"

	"github.com/dgenio/agentfence/internal/policy"
)

// Counters aggregates decision-level signal for a single run. Construct it with
// New. The zero value is not usable (its maps are nil); always use New.
type Counters struct {
	mu sync.Mutex

	byDecision   map[policy.Decision]int
	byTool       map[string]int
	byToolDecn   map[toolDecision]int
	byReasonCode map[policy.ReasonCode]int

	// Evaluation latency, summed for the proxies. evalCount and evalNanos
	// together yield mean latency without storing a histogram.
	evalCount uint64
	evalNanos int64

	// Operational errors by kind (e.g. "upstream", "proxy", "audit_write"),
	// used by the proxy /metrics endpoint to surface error rates.
	errors map[string]int
}

type toolDecision struct {
	tool     string
	decision policy.Decision
}

// New returns an empty, ready-to-use Counters.
func New() *Counters {
	return &Counters{
		byDecision:   map[policy.Decision]int{},
		byTool:       map[string]int{},
		byToolDecn:   map[toolDecision]int{},
		byReasonCode: map[policy.ReasonCode]int{},
		errors:       map[string]int{},
	}
}

// Record counts one evaluated decision. tool may be empty (e.g. a parse-error
// event); code may be ReasonCodeUnspecified for pre-taxonomy callers. Taint
// escalations and approval outcomes are derived from the reason code, so a
// single Record call captures every dimension.
func (c *Counters) Record(decision policy.Decision, tool string, code policy.ReasonCode) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.byDecision[decision]++
	if tool != "" {
		c.byTool[tool]++
		c.byToolDecn[toolDecision{tool: tool, decision: decision}]++
	}
	if code != "" {
		c.byReasonCode[code]++
	}
}

// ObserveEvalLatency adds one evaluation's latency to the running sum. It is a
// no-op for a negative duration.
func (c *Counters) ObserveEvalLatency(d time.Duration) {
	if d < 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.evalCount++
	c.evalNanos += d.Nanoseconds()
}

// RecordError increments the counter for an operational error of the given
// kind (e.g. "upstream", "proxy", "audit_write"). Empty kinds are ignored.
func (c *Counters) RecordError(kind string) {
	if kind == "" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.errors[kind]++
}

// Snapshot is an immutable point-in-time copy of a Counters, suitable for
// rendering as text, JSON, or Prometheus output without holding the lock.
type Snapshot struct {
	Total            int                  `json:"total"`
	ByDecision       map[string]int       `json:"by_decision"`
	ByTool           map[string]int       `json:"by_tool,omitempty"`
	ByReasonCode     map[string]int       `json:"by_reason_code,omitempty"`
	TaintEscalations int                  `json:"taint_escalations"`
	ApprovalOutcomes map[string]int       `json:"approval_outcomes,omitempty"`
	Errors           map[string]int       `json:"errors,omitempty"`
	EvalCount        uint64               `json:"eval_count"`
	EvalLatencyNanos int64                `json:"eval_latency_nanos"`
	byToolDecision   map[toolDecision]int `json:"-"`
}

// Snapshot returns an immutable copy of the current counts.
func (c *Counters) Snapshot() Snapshot {
	c.mu.Lock()
	defer c.mu.Unlock()

	s := Snapshot{
		ByDecision:       map[string]int{},
		ByTool:           map[string]int{},
		ByReasonCode:     map[string]int{},
		ApprovalOutcomes: map[string]int{},
		Errors:           map[string]int{},
		EvalCount:        c.evalCount,
		EvalLatencyNanos: c.evalNanos,
		byToolDecision:   map[toolDecision]int{},
	}
	for d, n := range c.byDecision {
		s.ByDecision[string(d)] += n
		s.Total += n
	}
	for t, n := range c.byTool {
		s.ByTool[t] = n
	}
	for td, n := range c.byToolDecn {
		s.byToolDecision[td] = n
	}
	for code, n := range c.byReasonCode {
		s.ByReasonCode[string(code)] = n
		if isApprovalCode(code) {
			s.ApprovalOutcomes[string(code)] = n
		}
	}
	s.TaintEscalations = c.byReasonCode[policy.ReasonCodeTaintEscalated] + c.byReasonCode[policy.ReasonCodeTaintDenied]
	for k, n := range c.errors {
		s.Errors[k] = n
	}
	return s
}

// isApprovalCode reports whether code classifies an ask-resolution outcome.
func isApprovalCode(code policy.ReasonCode) bool {
	switch code {
	case policy.ReasonCodeApprovalApproved,
		policy.ReasonCodeApprovalDenied,
		policy.ReasonCodeApprovalTimeout,
		policy.ReasonCodeApprovalCancelled,
		policy.ReasonCodeApprovalIOError,
		policy.ReasonCodeNonInteractive:
		return true
	}
	return false
}

// MeanEvalLatency returns the mean per-evaluation latency, or zero when no
// latencies were observed.
func (s Snapshot) MeanEvalLatency() time.Duration {
	if s.EvalCount == 0 {
		return 0
	}
	return time.Duration(s.EvalLatencyNanos / int64(s.EvalCount))
}

// FormatText renders s as a compact, deterministic human-readable summary on w.
// It is the on-exit summary for the CLI and proxies.
func (s Snapshot) FormatText(w io.Writer) error {
	ew := &errWriter{w: w}
	ew.printf("Decision metrics\n")
	ew.printf("  total decisions: %d\n", s.Total)
	ew.printf("  by decision:     allow=%d deny=%d ask=%d\n",
		s.ByDecision[string(policy.DecisionAllow)],
		s.ByDecision[string(policy.DecisionDeny)],
		s.ByDecision[string(policy.DecisionAsk)])
	ew.printf("  taint escalations: %d\n", s.TaintEscalations)

	if len(s.ApprovalOutcomes) > 0 {
		ew.printf("  approval outcomes:")
		for _, k := range sortedKeys(s.ApprovalOutcomes) {
			ew.printf(" %s=%d", k, s.ApprovalOutcomes[k])
		}
		ew.printf("\n")
	}
	if s.EvalCount > 0 {
		ew.printf("  mean eval latency: %s\n", s.MeanEvalLatency())
	}
	if len(s.Errors) > 0 {
		ew.printf("  errors:")
		for _, k := range sortedKeys(s.Errors) {
			ew.printf(" %s=%d", k, s.Errors[k])
		}
		ew.printf("\n")
	}
	if len(s.ByReasonCode) > 0 {
		ew.printf("  by reason code:\n")
		for _, code := range sortedKeys(s.ByReasonCode) {
			ew.printf("    %5d  %s\n", s.ByReasonCode[code], code)
		}
	}
	if len(s.ByTool) > 0 {
		ew.printf("  by tool:\n")
		for _, t := range sortedKeys(s.ByTool) {
			ew.printf("    %5d  %s\n", s.ByTool[t], t)
		}
	}
	return ew.err
}

// WritePrometheus renders s in the Prometheus text-exposition format on w. The
// metric set is intentionally small and stable: it mirrors the JSON Snapshot so
// the scrapable endpoint and the on-exit summary report the same numbers. This
// is a dependency-free emitter — it does not require the Prometheus client
// library — which keeps the default binary lean.
func (s Snapshot) WritePrometheus(w io.Writer) error {
	ew := &errWriter{w: w}

	ew.printf("# HELP agentfence_decisions_total Tool-call decisions by decision and reason code.\n")
	ew.printf("# TYPE agentfence_decisions_total counter\n")
	for _, td := range sortedToolDecisions(s.byToolDecision) {
		ew.printf("agentfence_decisions_total{tool=%q,decision=%q} %d\n",
			td.tool, string(td.decision), s.byToolDecision[td])
	}

	ew.printf("# HELP agentfence_taint_escalations_total Decisions adjusted by taint tracking.\n")
	ew.printf("# TYPE agentfence_taint_escalations_total counter\n")
	ew.printf("agentfence_taint_escalations_total %d\n", s.TaintEscalations)

	if len(s.ApprovalOutcomes) > 0 {
		ew.printf("# HELP agentfence_approval_outcomes_total Resolved ask-decision outcomes.\n")
		ew.printf("# TYPE agentfence_approval_outcomes_total counter\n")
		for _, k := range sortedKeys(s.ApprovalOutcomes) {
			ew.printf("agentfence_approval_outcomes_total{outcome=%q} %d\n", k, s.ApprovalOutcomes[k])
		}
	}

	ew.printf("# HELP agentfence_eval_latency_seconds_sum Total evaluation latency in seconds.\n")
	ew.printf("# TYPE agentfence_eval_latency_seconds_sum counter\n")
	ew.printf("agentfence_eval_latency_seconds_sum %g\n", time.Duration(s.EvalLatencyNanos).Seconds())
	ew.printf("# HELP agentfence_eval_latency_seconds_count Evaluations observed.\n")
	ew.printf("# TYPE agentfence_eval_latency_seconds_count counter\n")
	ew.printf("agentfence_eval_latency_seconds_count %d\n", s.EvalCount)

	if len(s.Errors) > 0 {
		ew.printf("# HELP agentfence_errors_total Operational errors by kind.\n")
		ew.printf("# TYPE agentfence_errors_total counter\n")
		for _, k := range sortedKeys(s.Errors) {
			ew.printf("agentfence_errors_total{kind=%q} %d\n", k, s.Errors[k])
		}
	}
	return ew.err
}

func sortedKeys(m map[string]int) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func sortedToolDecisions(m map[toolDecision]int) []toolDecision {
	out := make([]toolDecision, 0, len(m))
	for td := range m {
		out = append(out, td)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].tool != out[j].tool {
			return out[i].tool < out[j].tool
		}
		return out[i].decision < out[j].decision
	})
	return out
}

// errWriter mirrors the audit package's small accumulating writer so a report
// can be rendered with plain printf calls while still surfacing a write error.
type errWriter struct {
	w   io.Writer
	err error
}

func (ew *errWriter) printf(format string, args ...interface{}) {
	if ew.err != nil {
		return
	}
	_, ew.err = fmt.Fprintf(ew.w, format, args...)
}
