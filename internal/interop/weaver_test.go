package interop

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/dgenio/agentfence/internal/audit"
	"github.com/dgenio/agentfence/internal/policy"
)

func TestFromAuditEventDecisionMapping(t *testing.T) {
	tests := []struct {
		name          string
		decision      policy.Decision
		wantDecision  string
		wantEventType string
		wantOutcome   string
		wantEscalate  bool
	}{
		{
			name:          "allow maps to authorized",
			decision:      policy.DecisionAllow,
			wantDecision:  "allow",
			wantEventType: "capability_authorized",
			wantOutcome:   "success",
		},
		{
			name:          "deny maps to denied",
			decision:      policy.DecisionDeny,
			wantDecision:  "deny",
			wantEventType: "capability_denied",
			wantOutcome:   "failure",
		},
		{
			name:          "ask maps to denied with escalation",
			decision:      policy.DecisionAsk,
			wantDecision:  "deny",
			wantEventType: "capability_denied",
			wantOutcome:   "partial",
			wantEscalate:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := audit.Event{
				SchemaVersion: "2",
				SessionID:     "sess-1",
				Sequence:      7,
				Timestamp:     "2026-05-01T10:00:00Z",
				CallID:        "call_007",
				Tool:          "filesystem.write",
				Decision:      tt.decision,
				Reason:        "matched rule",
			}
			pd, te := FromAuditEvent(e)

			if pd.Decision != tt.wantDecision {
				t.Errorf("PolicyDecision.Decision = %q, want %q", pd.Decision, tt.wantDecision)
			}
			if te.EventType != tt.wantEventType {
				t.Errorf("TraceEvent.EventType = %q, want %q", te.EventType, tt.wantEventType)
			}
			if te.Outcome != tt.wantOutcome {
				t.Errorf("TraceEvent.Outcome = %q, want %q", te.Outcome, tt.wantOutcome)
			}

			// Invariant I-02: every PolicyDecision has a matching TraceEvent
			// linked by decision_id.
			if pd.DecisionID != te.DecisionID {
				t.Errorf("decision_id mismatch: pd=%q te=%q", pd.DecisionID, te.DecisionID)
			}
			if pd.DecisionID == "" {
				t.Error("decision_id is empty")
			}
			if pd.CapabilityID != "filesystem.write" {
				t.Errorf("PolicyDecision.CapabilityID = %q, want %q", pd.CapabilityID, "filesystem.write")
			}
			if pd.Principal != "sess-1" {
				t.Errorf("PolicyDecision.Principal = %q, want %q", pd.Principal, "sess-1")
			}

			// The original decision is always preserved verbatim in metadata.
			if got := pd.Metadata["agentfence_decision"]; got != string(tt.decision) {
				t.Errorf("metadata.agentfence_decision = %v, want %q", got, tt.decision)
			}
			_, hasEscalation := pd.Metadata["escalation"]
			if hasEscalation != tt.wantEscalate {
				t.Errorf("metadata.escalation present = %v, want %v", hasEscalation, tt.wantEscalate)
			}
			if tt.wantEscalate && pd.Metadata["escalation"] != "ask" {
				t.Errorf("metadata.escalation = %v, want %q", pd.Metadata["escalation"], "ask")
			}
		})
	}
}

func TestFromAuditEventEmptyToolUsesSentinel(t *testing.T) {
	// Synthetic parse-error events have no tool; weaver-spec requires a
	// non-empty capability_id.
	e := audit.NewErrorEvent(3, "bad json")
	e.SessionID = "sess-2"
	e.Sequence = 3

	pd, te := FromAuditEvent(e)
	if pd.CapabilityID != unknownCapability {
		t.Errorf("PolicyDecision.CapabilityID = %q, want %q", pd.CapabilityID, unknownCapability)
	}
	if te.CapabilityID != unknownCapability {
		t.Errorf("TraceEvent.CapabilityID = %q, want %q", te.CapabilityID, unknownCapability)
	}
	if pd.Decision != "deny" {
		t.Errorf("parse-error event Decision = %q, want %q", pd.Decision, "deny")
	}
}

func TestFromAuditEventCarriesChainHashes(t *testing.T) {
	e := audit.Event{
		SessionID: "sess-3",
		Sequence:  2,
		Tool:      "github.create_issue",
		Decision:  policy.DecisionAllow,
		Timestamp: "2026-05-01T10:00:00Z",
		PrevHash:  "aaaa",
		Hash:      "bbbb",
	}
	pd, te := FromAuditEvent(e)
	for _, m := range []map[string]interface{}{pd.Metadata, te.Metadata} {
		if m["prev_hash"] != "aaaa" {
			t.Errorf("metadata.prev_hash = %v, want %q", m["prev_hash"], "aaaa")
		}
		if m["hash"] != "bbbb" {
			t.Errorf("metadata.hash = %v, want %q", m["hash"], "bbbb")
		}
	}
}

func TestExportTracesPairsAndCounts(t *testing.T) {
	in := strings.Join([]string{
		`{"schema_version":"2","session_id":"demo","seq":1,"timestamp":"2026-05-01T10:00:00Z","call_id":"c1","tool":"filesystem.read","decision":"allow","reason":"ok"}`,
		`{"schema_version":"2","session_id":"demo","seq":2,"timestamp":"2026-05-01T10:00:01Z","call_id":"c2","tool":"filesystem.write","decision":"deny","reason":"blocked"}`,
		`{"schema_version":"2","session_id":"demo","seq":3,"timestamp":"2026-05-01T10:00:02Z","call_id":"c3","tool":"github.create_issue","decision":"ask","reason":"approval"}`,
	}, "\n") + "\n"

	var out bytes.Buffer
	n, err := ExportTraces(strings.NewReader(in), &out)
	if err != nil {
		t.Fatalf("ExportTraces returned error: %v", err)
	}
	if n != 3 {
		t.Fatalf("exported event count = %d, want 3", n)
	}

	lines := splitNonEmpty(out.String())
	if len(lines) != 6 {
		t.Fatalf("output line count = %d, want 6 (2 per event)", len(lines))
	}

	// Each event yields a PolicyDecision line then a TraceEvent line, paired by
	// decision_id.
	for i := 0; i < len(lines); i += 2 {
		var pd map[string]interface{}
		var te map[string]interface{}
		if err := json.Unmarshal([]byte(lines[i]), &pd); err != nil {
			t.Fatalf("line %d not JSON: %v", i, err)
		}
		if err := json.Unmarshal([]byte(lines[i+1]), &te); err != nil {
			t.Fatalf("line %d not JSON: %v", i+1, err)
		}
		if _, ok := pd["decision"]; !ok {
			t.Errorf("line %d: expected a PolicyDecision (has 'decision')", i)
		}
		if te["event_type"] == nil {
			t.Errorf("line %d: expected a TraceEvent (has 'event_type')", i+1)
		}
		if pd["decision_id"] != te["decision_id"] {
			t.Errorf("pair %d: decision_id mismatch pd=%v te=%v", i/2, pd["decision_id"], te["decision_id"])
		}
	}
}

func TestExportTracesMalformedLineErrors(t *testing.T) {
	in := "{\"session_id\":\"x\",\"seq\":1,\"tool\":\"t\",\"decision\":\"allow\"}\nnot-json\n"
	var out bytes.Buffer
	_, err := ExportTraces(strings.NewReader(in), &out)
	if err == nil {
		t.Fatal("expected an error for a malformed line, got nil")
	}
	if !strings.Contains(err.Error(), "line 2") {
		t.Errorf("error %q should name the offending line (line 2)", err.Error())
	}
}

func TestExportTracesSkipsBlankLines(t *testing.T) {
	in := "\n{\"session_id\":\"x\",\"seq\":1,\"tool\":\"t\",\"decision\":\"allow\"}\n\n"
	var out bytes.Buffer
	n, err := ExportTraces(strings.NewReader(in), &out)
	if err != nil {
		t.Fatalf("ExportTraces returned error: %v", err)
	}
	if n != 1 {
		t.Fatalf("exported event count = %d, want 1", n)
	}
	if got := len(splitNonEmpty(out.String())); got != 2 {
		t.Fatalf("output line count = %d, want 2", got)
	}
}

func splitNonEmpty(s string) []string {
	var out []string
	for _, ln := range strings.Split(s, "\n") {
		if strings.TrimSpace(ln) != "" {
			out = append(out, ln)
		}
	}
	return out
}
