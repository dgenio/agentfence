// The race detector adds its own allocations, so this file is excluded from
// -race runs. The behavior under test is the allocation profile of lookupRule,
// which only the plain build measures faithfully.

//go:build !race

package engine

import (
	"testing"

	"github.com/dgenio/agentfence/internal/policy"
)

// TestLookupRuleDoesNotAllocate pins the precompute win from the former
// TODO(perf) in lookupRule: sorted group names and wildcard pattern keys are
// built once in New, so a lookup that resolves through the group path performs
// zero allocations. Before the precompute, every lookup that passed the
// exact-match step allocated and sorted the group-name slice, so this test
// fails on the pre-change implementation.
func TestLookupRuleDoesNotAllocate(t *testing.T) {
	corpus := newBenchmarkCorpus(benchmarkCorpusSpec{
		callCount:     8,
		groupCount:    4,
		wildcardCount: 4,
	})
	eng, err := New(corpus.policy)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	// service-000-read matches group-000, the first group in sorted order,
	// through path.Match alone. The lookup therefore exercises the exact-miss
	// and group-scan steps without entering the regex fallback of matchesGlob,
	// which allocates by design when a glob needs ** handling.
	rule, found, key := eng.lookupRule("service-000-read")
	if !found || key != "group-000" || rule.Decision != policy.DecisionAllow {
		t.Fatalf("lookupRule() = found %v, key %q, decision %q; want group-000 allow", found, key, rule.Decision)
	}

	allocs := testing.AllocsPerRun(100, func() {
		eng.lookupRule("service-000-read")
	})
	if allocs != 0 {
		t.Fatalf("lookupRule allocated %.1f times per call; want 0", allocs)
	}
}
