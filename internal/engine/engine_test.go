package engine

import (
	"testing"

	"github.com/dgenio/agentfence/internal/policy"
)

func TestExplicitAllow(t *testing.T) {
	e := mustEngine(t)
	res, _ := e.Evaluate(policy.ToolCall{ID: "1", Tool: "filesystem.read", Arguments: map[string]interface{}{"path": "README.md"}})
	if res.Decision != policy.DecisionAllow {
		t.Fatalf("expected allow, got %s", res.Decision)
	}
}

func TestExplicitDeny(t *testing.T) {
	e := mustEngine(t)
	res, _ := e.Evaluate(policy.ToolCall{ID: "1", Tool: "github.delete_repo", Arguments: map[string]interface{}{"repo": "x/y"}})
	if res.Decision != policy.DecisionDeny {
		t.Fatalf("expected deny, got %s", res.Decision)
	}
}

func TestDefaultDeny(t *testing.T) {
	e := mustEngine(t)
	res, _ := e.Evaluate(policy.ToolCall{ID: "1", Tool: "shell.exec", Arguments: map[string]interface{}{}})
	if res.Decision != policy.DecisionDeny {
		t.Fatalf("expected deny, got %s", res.Decision)
	}
}

func TestAskDecision(t *testing.T) {
	e := mustEngine(t)
	res, _ := e.Evaluate(policy.ToolCall{ID: "1", Tool: "github.create_issue", Arguments: map[string]interface{}{"repo": "x/y"}})
	if res.Decision != policy.DecisionAsk {
		t.Fatalf("expected ask, got %s", res.Decision)
	}
}

func TestPathAllow(t *testing.T) {
	e := mustEngine(t)
	res, _ := e.Evaluate(policy.ToolCall{ID: "1", Tool: "filesystem.write", Arguments: map[string]interface{}{"path": "docs/readme.md"}})
	if res.Decision != policy.DecisionAsk {
		t.Fatalf("expected ask, got %s", res.Decision)
	}
}

func TestPathDeny(t *testing.T) {
	e := mustEngine(t)
	res, _ := e.Evaluate(policy.ToolCall{ID: "1", Tool: "filesystem.write", Arguments: map[string]interface{}{"path": ".env"}})
	if res.Decision != policy.DecisionDeny {
		t.Fatalf("expected deny, got %s", res.Decision)
	}
}

func TestDenyOverridesAllow(t *testing.T) {
	p, err := policy.ParsePolicy([]byte(`version: "0.1"
defaults:
  decision: deny
tools:
  filesystem.write:
    decision: allow
    constraints:
      paths:
        allow: ["./**"]
        deny: ["./secrets/**"]
`))
	if err != nil {
		t.Fatalf("ParsePolicy error: %v", err)
	}
	e, err := New(p)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	res, _ := e.Evaluate(policy.ToolCall{ID: "1", Tool: "filesystem.write", Arguments: map[string]interface{}{"path": "secrets/token.txt"}})
	if res.Decision != policy.DecisionDeny {
		t.Fatalf("expected deny, got %s", res.Decision)
	}
}

func mustEngine(t *testing.T) *Engine {
	t.Helper()
	p, err := policy.ParsePolicy([]byte(policy.StarterPolicyYAML))
	if err != nil {
		t.Fatalf("ParsePolicy error: %v", err)
	}
	e, err := New(p)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return e
}
