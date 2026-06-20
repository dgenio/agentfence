package engine

import (
	"testing"

	"github.com/dgenio/agentfence/internal/policy"
)

// reasonCodePolicy exercises every constraint family so each decision path can
// be asserted to carry the right stable ReasonCode (#136).
const reasonCodePolicy = `version: "0.1"
defaults:
  decision: deny
tools:
  fs.read:
    decision: allow
    constraints:
      paths:
        allow: ["src/**"]
        deny: ["**/.env"]
  http.fetch:
    decision: allow
    constraints:
      urls:
        allow: ["https://api.example.com/**"]
  shell.exec:
    decision: allow
    constraints:
      command:
        allow_executables: ["git"]
        deny_patterns: ["*rm*"]
  args.tool:
    decision: allow
    constraints:
      args:
        mode:
          allow: ["read"]
  mem.write:
    decision: allow
    constraints:
      memory_write:
        max_scope: session
        max_bytes: 8
  plain.allow:
    decision: allow
`

func TestEvaluateSetsReasonCode(t *testing.T) {
	p, err := policy.ParsePolicy([]byte(reasonCodePolicy))
	if err != nil {
		t.Fatalf("ParsePolicy error: %v", err)
	}
	e, err := New(p)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	tests := []struct {
		name     string
		call     policy.ToolCall
		wantDec  policy.Decision
		wantCode policy.ReasonCode
	}{
		{
			name:     "rule match allow",
			call:     policy.ToolCall{ID: "1", Tool: "plain.allow", Arguments: map[string]interface{}{}},
			wantDec:  policy.DecisionAllow,
			wantCode: policy.ReasonCodeRuleMatch,
		},
		{
			name:     "no rule uses default",
			call:     policy.ToolCall{ID: "1", Tool: "unknown.tool", Arguments: map[string]interface{}{}},
			wantDec:  policy.DecisionDeny,
			wantCode: policy.ReasonCodeDefaultDecision,
		},
		{
			name:     "path missing",
			call:     policy.ToolCall{ID: "1", Tool: "fs.read", Arguments: map[string]interface{}{}},
			wantDec:  policy.DecisionDeny,
			wantCode: policy.ReasonCodePathMissing,
		},
		{
			name:     "path unsafe (absolute)",
			call:     policy.ToolCall{ID: "1", Tool: "fs.read", Arguments: map[string]interface{}{"path": "/etc/passwd"}},
			wantDec:  policy.DecisionDeny,
			wantCode: policy.ReasonCodePathUnsafe,
		},
		{
			name:     "path denied by pattern",
			call:     policy.ToolCall{ID: "1", Tool: "fs.read", Arguments: map[string]interface{}{"path": "src/.env"}},
			wantDec:  policy.DecisionDeny,
			wantCode: policy.ReasonCodePathDenied,
		},
		{
			name:     "path not in allow list",
			call:     policy.ToolCall{ID: "1", Tool: "fs.read", Arguments: map[string]interface{}{"path": "docs/readme.md"}},
			wantDec:  policy.DecisionDeny,
			wantCode: policy.ReasonCodePathNotAllowed,
		},
		{
			name:     "url bare ip always denied",
			call:     policy.ToolCall{ID: "1", Tool: "http.fetch", Arguments: map[string]interface{}{"url": "http://10.0.0.1/x"}},
			wantDec:  policy.DecisionDeny,
			wantCode: policy.ReasonCodeURLBareIP,
		},
		{
			name:     "url not allowed",
			call:     policy.ToolCall{ID: "1", Tool: "http.fetch", Arguments: map[string]interface{}{"url": "https://evil.example.org/x"}},
			wantDec:  policy.DecisionDeny,
			wantCode: policy.ReasonCodeURLNotAllowed,
		},
		{
			name:     "command denied by pattern",
			call:     policy.ToolCall{ID: "1", Tool: "shell.exec", Arguments: map[string]interface{}{"command": "git rm secret"}},
			wantDec:  policy.DecisionDeny,
			wantCode: policy.ReasonCodeCommandDenied,
		},
		{
			name:     "command executable not allowed",
			call:     policy.ToolCall{ID: "1", Tool: "shell.exec", Arguments: map[string]interface{}{"command": "curl http://x"}},
			wantDec:  policy.DecisionDeny,
			wantCode: policy.ReasonCodeCommandExecNotAllowed,
		},
		{
			name:     "arg not allowed",
			call:     policy.ToolCall{ID: "1", Tool: "args.tool", Arguments: map[string]interface{}{"mode": "write"}},
			wantDec:  policy.DecisionDeny,
			wantCode: policy.ReasonCodeArgNotAllowed,
		},
		{
			name:     "memory size exceeded",
			call:     policy.ToolCall{ID: "1", Tool: "mem.write", Arguments: map[string]interface{}{"value": "way too long payload"}},
			wantDec:  policy.DecisionDeny,
			wantCode: policy.ReasonCodeMemorySizeExceeded,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res, event := e.Evaluate(tt.call)
			if res.Decision != tt.wantDec {
				t.Fatalf("decision = %s, want %s (reason: %s)", res.Decision, tt.wantDec, res.Reason)
			}
			if res.ReasonCode != tt.wantCode {
				t.Errorf("ReasonCode = %q, want %q", res.ReasonCode, tt.wantCode)
			}
			// The audit event must carry the same code as the result.
			if event.ReasonCode != tt.wantCode {
				t.Errorf("event.ReasonCode = %q, want %q", event.ReasonCode, tt.wantCode)
			}
			// The free-text reason must remain populated (taxonomy is additive).
			if res.Reason == "" {
				t.Errorf("Reason is empty; the human-readable reason must be preserved")
			}
		})
	}
}

// TestTaintEscalationReasonCode verifies the session evaluator sets the taint
// escalation code when an argument is derived from untrusted output.
func TestTaintEscalationReasonCode(t *testing.T) {
	p, err := policy.ParsePolicy([]byte(`version: "0.1"
defaults:
  decision: deny
taint:
  enabled: true
  min_length: 4
  on_tainted_argument: escalate
tools:
  sink.tool:
    decision: allow
  source.tool:
    decision: allow
`))
	if err != nil {
		t.Fatalf("ParsePolicy error: %v", err)
	}
	e, err := New(p)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	sess := e.NewSession()
	sess.ObserveResult("source.tool", "SECRETVALUE")

	res, event := sess.Evaluate(policy.ToolCall{
		ID:        "1",
		Tool:      "sink.tool",
		Arguments: map[string]interface{}{"data": "SECRETVALUE"},
	})
	if res.Decision != policy.DecisionAsk {
		t.Fatalf("expected escalate allow->ask, got %s", res.Decision)
	}
	if res.ReasonCode != policy.ReasonCodeTaintEscalated {
		t.Errorf("ReasonCode = %q, want %q", res.ReasonCode, policy.ReasonCodeTaintEscalated)
	}
	if event.ReasonCode != policy.ReasonCodeTaintEscalated {
		t.Errorf("event.ReasonCode = %q, want %q", event.ReasonCode, policy.ReasonCodeTaintEscalated)
	}
}
