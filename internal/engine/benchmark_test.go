package engine

import (
	"fmt"
	"testing"

	"github.com/dgenio/agentfence/internal/policy"
)

type benchmarkCorpusSpec struct {
	callCount     int
	groupCount    int
	wildcardCount int
}

type benchmarkCorpus struct {
	policy policy.Policy
	calls  []policy.ToolCall
}

func newBenchmarkCorpus(spec benchmarkCorpusSpec) benchmarkCorpus {
	p := policy.Policy{
		Defaults: policy.Defaults{Decision: policy.DecisionDeny},
		Groups:   make(map[string][]string, spec.groupCount),
		Tools:    make(map[string]policy.Rule, spec.groupCount+spec.wildcardCount+1),
	}

	for i := 0; i < spec.groupCount; i++ {
		name := fmt.Sprintf("group-%03d", i)
		p.Groups[name] = []string{fmt.Sprintf("service-%03d-*", i)}
		p.Tools[name] = policy.Rule{Decision: policy.DecisionAllow}
	}
	for i := 0; i < spec.wildcardCount; i++ {
		name := fmt.Sprintf("fallback-%03d-*", i)
		p.Tools[name] = policy.Rule{Decision: policy.DecisionAsk}
	}
	p.Tools["exact.allow"] = policy.Rule{Decision: policy.DecisionAllow}

	calls := make([]policy.ToolCall, spec.callCount)
	for i := range calls {
		tool := "exact.allow"
		switch i % 4 {
		case 0:
			tool = fmt.Sprintf("service-%03d-read", (i/4)%spec.groupCount)
		case 1:
			tool = fmt.Sprintf("fallback-%03d-read", (i/4)%spec.wildcardCount)
		case 3:
			tool = fmt.Sprintf("unknown-%06d", i)
		}
		calls[i] = policy.ToolCall{
			ID:   fmt.Sprintf("bench-%06d", i),
			Tool: tool,
			Arguments: map[string]interface{}{
				"path": fmt.Sprintf("workspace/%06d.txt", i),
			},
		}
	}

	return benchmarkCorpus{policy: p, calls: calls}
}

func TestBenchmarkCorpusIsDeterministic(t *testing.T) {
	corpus := newBenchmarkCorpus(benchmarkCorpusSpec{
		callCount:     8,
		groupCount:    2,
		wildcardCount: 2,
	})

	if got, want := len(corpus.calls), 8; got != want {
		t.Fatalf("call count = %d, want %d", got, want)
	}
	if got, want := len(corpus.policy.Groups), 2; got != want {
		t.Fatalf("group count = %d, want %d", got, want)
	}
	if got, want := len(corpus.policy.Tools), 5; got != want {
		t.Fatalf("tool rule count = %d, want %d", got, want)
	}

	first := corpus.calls[0]
	if first.ID != "bench-000000" || first.Tool != "service-000-read" {
		t.Fatalf("first call = %#v, want ID bench-000000 and tool service-000-read", first)
	}
	last := corpus.calls[len(corpus.calls)-1]
	if last.ID != "bench-000007" || last.Tool != "unknown-000007" {
		t.Fatalf("last call = %#v, want ID bench-000007 and tool unknown-000007", last)
	}
}

func TestBenchmarkCorpusEvaluationDistribution(t *testing.T) {
	corpus := newBenchmarkCorpus(benchmarkCorpusSpec{
		callCount:     400,
		groupCount:    8,
		wildcardCount: 8,
	})
	eng, err := New(corpus.policy)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	counts := map[policy.Decision]int{}
	for _, call := range corpus.calls {
		result, _ := eng.Evaluate(call)
		counts[result.Decision]++
	}

	want := map[policy.Decision]int{
		policy.DecisionAllow: 200,
		policy.DecisionAsk:   100,
		policy.DecisionDeny:  100,
	}
	for decision, wantCount := range want {
		if got := counts[decision]; got != wantCount {
			t.Errorf("%s count = %d, want %d", decision, got, wantCount)
		}
	}
}

var benchmarkEvaluationDecision policy.Decision

func BenchmarkEvaluateLargeTrace(b *testing.B) {
	tiers := []benchmarkCorpusSpec{
		{callCount: 10_000, groupCount: 16, wildcardCount: 16},
		{callCount: 50_000, groupCount: 64, wildcardCount: 64},
	}

	for _, tier := range tiers {
		name := fmt.Sprintf("N=%d/M=%d", tier.callCount, tier.groupCount)
		b.Run(name, func(b *testing.B) {
			corpus := newBenchmarkCorpus(tier)
			eng, err := New(corpus.policy)
			if err != nil {
				b.Fatalf("New() error = %v", err)
			}

			b.ReportAllocs()
			b.ResetTimer()

			var decision policy.Decision
			for i := 0; i < b.N; i++ {
				result, _ := eng.Evaluate(corpus.calls[i%len(corpus.calls)])
				decision = result.Decision
			}
			benchmarkEvaluationDecision = decision
			b.StopTimer()
			b.ReportMetric(float64(tier.callCount), "trace_calls")
			b.ReportMetric(float64(tier.groupCount), "groups")
			b.ReportMetric(float64(tier.wildcardCount), "wildcards")
		})
	}
}
