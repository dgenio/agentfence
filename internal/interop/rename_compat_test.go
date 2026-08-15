package interop

import (
	"testing"

	"github.com/dgenio/agentfence/internal/audit"
	"github.com/dgenio/agentfence/internal/policy"
)

func TestRenamePreservesWeaverV0HistoricalNamespace(t *testing.T) {
	event := audit.Event{
		SchemaVersion: "4",
		Sequence:      7,
		Timestamp:     "2026-08-01T12:00:00Z",
		Decision:      policy.DecisionAsk,
	}
	pd, te := FromAuditEvent(event)

	if pd.CapabilityID != "agentfence.unknown" || te.CapabilityID != "agentfence.unknown" {
		t.Fatalf("unknown capability changed: policy=%q trace=%q", pd.CapabilityID, te.CapabilityID)
	}
	if pd.Principal != "agentfence.unknown-session" || te.Principal != "agentfence.unknown-session" {
		t.Fatalf("unknown principal changed: policy=%q trace=%q", pd.Principal, te.Principal)
	}
	if got := pd.Metadata["agentfence_decision"]; got != "ask" {
		t.Fatalf("agentfence_decision=%v, want ask", got)
	}
	if got := pd.Metadata["agentfence_schema_version"]; got != "4" {
		t.Fatalf("agentfence_schema_version=%v, want 4", got)
	}
	if _, ok := pd.Metadata["vericordon_decision"]; ok {
		t.Fatal("current Weaver v0 mapping must not silently rename agentfence_decision")
	}
}
