package engine

import (
	"testing"

	"github.com/dgenio/agentfence/internal/policy"
)

// This file collects regression tests for AgentFence's fail-closed invariants:
// the properties that guarantee an evaluation never silently grants access when
// something is unspecified, malformed, or unmatched. Each test pins one
// invariant so it fails loudly if a future change weakens it. The invariants
// are documented in docs/threat-model.md ("Fail-closed invariants").

func mustEngineFromYAML(t *testing.T, yaml string) *Engine {
	t.Helper()
	p, err := policy.ParsePolicy([]byte(yaml))
	if err != nil {
		t.Fatalf("ParsePolicy error: %v", err)
	}
	e, err := New(p)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return e
}

// Invariant: a tool with no matching rule receives defaults.decision — not a
// hardcoded value — so the policy author's chosen default always governs
// unmatched calls.
func TestFailClosedNoRuleUsesDefault(t *testing.T) {
	tests := []struct {
		name string
		def  string
		want policy.Decision
	}{
		{"default deny", "deny", policy.DecisionDeny},
		{"default ask", "ask", policy.DecisionAsk},
		{"default allow", "allow", policy.DecisionAllow},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := mustEngineFromYAML(t, `version: "0.1"
defaults:
  decision: `+tt.def+`
tools:
  filesystem.read:
    decision: allow
`)
			res, _ := e.Evaluate(policy.ToolCall{ID: "1", Tool: "unmatched.tool", Arguments: map[string]interface{}{}})
			if res.Decision != tt.want {
				t.Fatalf("unmatched tool with default %q: decision = %s, want %s", tt.def, res.Decision, tt.want)
			}
		})
	}
}

// Invariant: when defaults.decision is omitted entirely, the parser supplies
// deny, so an otherwise-empty policy denies every unmatched call by default.
func TestFailClosedDefaultIsDenyWhenOmitted(t *testing.T) {
	e := mustEngineFromYAML(t, `version: "0.1"
tools:
  filesystem.read:
    decision: allow
`)
	res, _ := e.Evaluate(policy.ToolCall{ID: "1", Tool: "anything.else", Arguments: map[string]interface{}{}})
	if res.Decision != policy.DecisionDeny {
		t.Fatalf("expected default deny when defaults omitted, got %s", res.Decision)
	}
}

// Invariant: a non-matching wildcard rule never grants access — the call falls
// through to the default decision rather than the wildcard rule's decision.
func TestFailClosedNonMatchingWildcardFallsToDefault(t *testing.T) {
	e := mustEngineFromYAML(t, `version: "0.1"
defaults:
  decision: deny
tools:
  filesystem.*:
    decision: allow
`)
	res, _ := e.Evaluate(policy.ToolCall{ID: "1", Tool: "github.delete_repo", Arguments: map[string]interface{}{}})
	if res.Decision != policy.DecisionDeny {
		t.Fatalf("non-matching wildcard should fall to default deny, got %s: %s", res.Decision, res.Reason)
	}
}

// Invariant: a tool that opts in to a constraint family but omits the required
// argument is denied, never allowed on the missing input.
func TestFailClosedMissingConstrainedArgumentDenied(t *testing.T) {
	e := mustEngineFromYAML(t, `version: "0.1"
defaults:
  decision: deny
tools:
  fs.read:
    decision: allow
    constraints:
      paths:
        allow:
          - "./src/**"
  gh.issue:
    decision: allow
    constraints:
      args:
        repo:
          allow:
            - "org/*"
  web.get:
    decision: allow
    constraints:
      urls:
        allow:
          - "https://**"
  sh.exec:
    decision: allow
    constraints:
      command:
        allow_executables:
          - "git"
`)

	tests := []struct {
		name string
		tool string
		args map[string]interface{}
	}{
		{"missing path", "fs.read", map[string]interface{}{}},
		{"missing arg field", "gh.issue", map[string]interface{}{}},
		{"missing url", "web.get", map[string]interface{}{}},
		{"missing command", "sh.exec", map[string]interface{}{}},
		{"empty command", "sh.exec", map[string]interface{}{"command": ""}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res, _ := e.Evaluate(policy.ToolCall{ID: "1", Tool: tt.tool, Arguments: tt.args})
			if res.Decision != policy.DecisionDeny {
				t.Fatalf("%s: expected deny, got %s: %s", tt.name, res.Decision, res.Reason)
			}
		})
	}
}

// Invariant: an unrecognised memory-write scope is denied rather than treated
// as the narrowest scope.
func TestFailClosedUnknownMemoryScopeDenied(t *testing.T) {
	e := mustEngineFromYAML(t, `version: "0.1"
defaults:
  decision: deny
tools:
  mem.write:
    decision: allow
    constraints:
      memory_write:
        max_scope: project
`)
	res, _ := e.Evaluate(policy.ToolCall{
		ID:   "1",
		Tool: "mem.write",
		Arguments: map[string]interface{}{
			"scope": "galaxy",
			"value": "x",
		},
	})
	if res.Decision != policy.DecisionDeny {
		t.Fatalf("unknown memory scope should deny, got %s: %s", res.Decision, res.Reason)
	}
}

// Invariant: an unknown decision string can never reach the engine because the
// parser rejects it. This is the enforcement point for the "unknown decision
// => deny" guarantee: the engine trusts that decisions are one of allow/deny/
// ask, and the parser guarantees that.
func TestFailClosedParserRejectsUnknownDecision(t *testing.T) {
	_, err := policy.ParsePolicy([]byte(`version: "0.1"
defaults:
  decision: deny
tools:
  some.tool:
    decision: maybe
`))
	if err == nil {
		t.Fatal("expected ParsePolicy to reject an unknown decision, got nil error")
	}
}

// Invariant: matchesGlob degrades to "no match" (never a panic, never a spurious
// match) for adversarial patterns and values. A non-match means the call falls
// through to the policy default, which is deny for a sound policy — so a
// pathological pattern can never silently grant access.
func TestFailClosedGlobNeverPanicsOrOverMatches(t *testing.T) {
	patterns := []string{"", "*", "**", "[", "\\", "a/**/b", "***", "[a-", "(.*)"}
	values := []string{"", "x", "a/b/c", "../etc", "[", "\\\\"}
	for _, p := range patterns {
		for _, v := range values {
			// Must not panic.
			got := matchesGlob(p, v)
			// The empty pattern must not match a non-empty value.
			if p == "" && v != "" && got {
				t.Fatalf("empty pattern unexpectedly matched %q", v)
			}
		}
	}
}
