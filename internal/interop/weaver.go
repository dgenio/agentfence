// Package interop maps AgentFence's native audit decision records onto the
// weaver-spec shared contracts (https://github.com/dgenio/weaver-spec) so that
// AgentFence findings can flow into Weaver Stack consumers such as lessonweaver.
//
// The mapping is additive and read-only: it never changes AgentFence's native
// JSONL audit format and never mutates an existing audit log, so the
// hash-chained tamper-evidence written by internal/audit (verifiable with
// `agentfence audit verify`) is preserved. Each emitted artifact carries the
// source event's prev_hash/hash in metadata so a consumer can cross-check the
// export against the native chain.
//
// Targeted contract release: weaver-spec v0 (contract version 0.6.0). See
// docs/interop.md for the field-by-field mapping and the limitations of the
// allow/deny/ask -> allow/deny projection.
package interop

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/dgenio/agentfence/internal/audit"
	"github.com/dgenio/agentfence/internal/policy"
)

// ContractVersion is the weaver-spec contract release these mappings target.
// SchemaVersionPrefix is the matching JSON Schema $id major-version prefix.
const (
	ContractVersion     = "0.6.0"
	SchemaVersionPrefix = "v0"
)

// weaver-spec TraceEvent.event_type and PolicyDecision.decision values used by
// the mapping. weaver-spec defines a larger event_type enum; an external policy
// edge like AgentFence only ever authorizes or denies a call, so the mapping
// uses the two authorization event types.
const (
	eventCapabilityAuthorized = "capability_authorized"
	eventCapabilityDenied     = "capability_denied"

	decisionAllow = "allow"
	decisionDeny  = "deny"

	outcomeSuccess = "success"
	outcomeFailure = "failure"
	outcomePartial = "partial"
)

// unknownCapability is used as capability_id when a source event has no tool
// (for example a synthetic parse-error deny event). weaver-spec requires
// capability_id to be a non-empty string.
const unknownCapability = "agentfence.unknown"

// unknownPrincipal is used as principal when a source event has no session id.
// In practice the audit Writer always sets a session id; the fallback only
// guards hand-written or truncated logs.
const unknownPrincipal = "agentfence.unknown-session"

// PolicyDecision mirrors weaver-spec v0 policy_decision.schema.json: the
// authorization verdict produced for a capability invocation. Fields AgentFence
// never populates (token_id) are omitted rather than emitted as null.
type PolicyDecision struct {
	DecisionID   string                 `json:"decision_id"`
	Decision     string                 `json:"decision"`
	CapabilityID string                 `json:"capability_id"`
	Principal    string                 `json:"principal"`
	Reason       string                 `json:"reason,omitempty"`
	Timestamp    string                 `json:"timestamp"`
	Metadata     map[string]interface{} `json:"metadata,omitempty"`
}

// TraceEvent mirrors weaver-spec v0 trace_event.schema.json: an immutable audit
// log entry for a single significant event, linked to its PolicyDecision by
// decision_id (weaver-spec invariant I-02).
type TraceEvent struct {
	EventID      string                 `json:"event_id"`
	EventType    string                 `json:"event_type"`
	Timestamp    string                 `json:"timestamp"`
	CapabilityID string                 `json:"capability_id,omitempty"`
	Principal    string                 `json:"principal,omitempty"`
	DecisionID   string                 `json:"decision_id,omitempty"`
	Outcome      string                 `json:"outcome,omitempty"`
	Metadata     map[string]interface{} `json:"metadata,omitempty"`
}

// FromAuditEvent converts one AgentFence audit event into the pair of
// weaver-spec artifacts that represent it: a PolicyDecision (the verdict) and a
// matching TraceEvent (the audit entry), sharing a decision_id per weaver-spec
// invariant I-02.
//
// weaver-spec's PolicyDecision.decision enum is allow|deny only. AgentFence's
// third decision, "ask" (escalate for human approval), has no weaver-spec
// equivalent, so it projects to "deny" (not authorized to proceed unattended)
// with the original decision preserved in metadata.agentfence_decision and
// metadata.escalation = "ask".
func FromAuditEvent(e audit.Event) (PolicyDecision, TraceEvent) {
	capID := e.Tool
	if capID == "" {
		capID = unknownCapability
	}
	principal := e.SessionID
	if principal == "" {
		principal = unknownPrincipal
	}
	decisionID := fmt.Sprintf("pd-%s-%d", principal, e.Sequence)
	eventID := fmt.Sprintf("te-%s-%d", principal, e.Sequence)

	decision, eventType, outcome := mapDecision(e.Decision)

	meta := map[string]interface{}{
		"agentfence_decision": string(e.Decision),
		"audit_log_sequence":  e.Sequence,
	}
	if e.SchemaVersion != "" {
		meta["agentfence_schema_version"] = e.SchemaVersion
	}
	if e.Mode != "" {
		meta["mode"] = e.Mode
	}
	if e.Decision == policy.DecisionAsk {
		meta["escalation"] = "ask"
	}
	if e.PrevHash != "" {
		meta["prev_hash"] = e.PrevHash
	}
	if e.Hash != "" {
		meta["hash"] = e.Hash
	}
	if e.MemoryWrite != nil {
		meta["memory_write"] = e.MemoryWrite
	}

	pd := PolicyDecision{
		DecisionID:   decisionID,
		Decision:     decision,
		CapabilityID: capID,
		Principal:    principal,
		Reason:       e.Reason,
		Timestamp:    e.Timestamp,
		Metadata:     meta,
	}
	te := TraceEvent{
		EventID:      eventID,
		EventType:    eventType,
		Timestamp:    e.Timestamp,
		CapabilityID: capID,
		Principal:    principal,
		DecisionID:   decisionID,
		Outcome:      outcome,
		// A distinct copy so callers mutating one artifact's Metadata cannot
		// affect the other (the two maps are otherwise identical).
		Metadata: cloneMeta(meta),
	}
	return pd, te
}

// cloneMeta returns a shallow copy of m. The values are shared, but the map
// itself is independent, so the two artifacts FromAuditEvent returns do not
// alias each other's Metadata.
func cloneMeta(m map[string]interface{}) map[string]interface{} {
	out := make(map[string]interface{}, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// mapDecision projects an AgentFence decision onto weaver-spec's
// allow/deny verdict, capability event type, and high-level outcome.
func mapDecision(d policy.Decision) (decision, eventType, outcome string) {
	switch d {
	case policy.DecisionAllow:
		return decisionAllow, eventCapabilityAuthorized, outcomeSuccess
	case policy.DecisionAsk:
		// Escalation: not an unattended authorization, recorded as a denied
		// capability with a "partial" outcome (a human decision is pending).
		return decisionDeny, eventCapabilityDenied, outcomePartial
	default:
		// Deny, and any unexpected value, fail closed to a denied capability.
		return decisionDeny, eventCapabilityDenied, outcomeFailure
	}
}

// validateSourceEvent rejects a decoded record that is not a well-formed
// AgentFence audit event. It requires the fields the audit Writer always
// populates and that weaver-spec needs to produce conformant, uniquely
// identified artifacts: a decision, a timestamp (weaver-spec requires it), and
// a non-zero sequence (the per-session counter that makes decision_id/event_id
// unique). Exporting a partially-formed record would emit non-conformant output
// (empty timestamp, colliding seq=0 IDs), so the exporter fails fast instead.
func validateSourceEvent(e audit.Event) error {
	if e.Decision == "" {
		return errors.New("not an audit event (missing decision)")
	}
	if e.Timestamp == "" {
		return errors.New("audit event missing timestamp (required by weaver-spec)")
	}
	if e.Sequence == 0 {
		return errors.New("audit event missing seq (would produce non-unique trace IDs)")
	}
	return nil
}

// ExportTraces reads AgentFence native JSONL audit events from r and writes a
// weaver-spec-aligned JSONL stream to w. For each source event it writes two
// lines — a PolicyDecision followed by its matching TraceEvent — so the output
// can be consumed by Weaver Stack tools (e.g. lessonweaver). It returns the
// number of source events exported.
//
// r is never written to and the native log is untouched, so its hash chain
// remains verifiable. A malformed (non-JSON, or JSON that is not an audit
// event) line aborts the export with an error naming the line number: silently
// dropping records from an audit export would undermine its integrity.
func ExportTraces(r io.Reader, w io.Writer) (int, error) {
	br := bufio.NewReader(r)
	enc := json.NewEncoder(w)

	count := 0
	lineNum := 0
	for {
		raw, readErr := br.ReadBytes('\n')
		raw = bytes.TrimRight(raw, "\r\n")

		if len(bytes.TrimSpace(raw)) == 0 {
			if readErr != nil {
				if readErr == io.EOF {
					break
				}
				return count, fmt.Errorf("interop: read input: %w", readErr)
			}
			lineNum++
			continue
		}
		lineNum++

		var e audit.Event
		if err := json.Unmarshal(raw, &e); err != nil {
			return count, fmt.Errorf("interop: line %d: not valid JSON: %w", lineNum, err)
		}
		if err := validateSourceEvent(e); err != nil {
			return count, fmt.Errorf("interop: line %d: %w", lineNum, err)
		}

		pd, te := FromAuditEvent(e)
		if err := enc.Encode(pd); err != nil {
			return count, fmt.Errorf("interop: encode policy decision: %w", err)
		}
		if err := enc.Encode(te); err != nil {
			return count, fmt.Errorf("interop: encode trace event: %w", err)
		}
		count++

		if readErr != nil {
			if readErr == io.EOF {
				break
			}
			return count, fmt.Errorf("interop: read input: %w", readErr)
		}
	}
	return count, nil
}
