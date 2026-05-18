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

func TestAbsolutePathDenied(t *testing.T) {
	e := mustEngine(t)
	res, _ := e.Evaluate(policy.ToolCall{ID: "1", Tool: "filesystem.read", Arguments: map[string]interface{}{"path": "/etc/passwd"}})
	if res.Decision != policy.DecisionDeny {
		t.Fatalf("expected deny for absolute path, got %s: %s", res.Decision, res.Reason)
	}
}

func TestTraversalPathDenied(t *testing.T) {
	e := mustEngine(t)
	res, _ := e.Evaluate(policy.ToolCall{ID: "1", Tool: "filesystem.read", Arguments: map[string]interface{}{"path": "../../etc/passwd"}})
	if res.Decision != policy.DecisionDeny {
		t.Fatalf("expected deny for traversal path, got %s: %s", res.Decision, res.Reason)
	}
}

func TestRelativePathAllowed(t *testing.T) {
	e := mustEngine(t)
	res, _ := e.Evaluate(policy.ToolCall{ID: "1", Tool: "filesystem.read", Arguments: map[string]interface{}{"path": "src/main.go"}})
	if res.Decision != policy.DecisionAllow {
		t.Fatalf("expected allow for relative path, got %s: %s", res.Decision, res.Reason)
	}
}

func TestDoubleStarDenyMatchesRootLevel(t *testing.T) {
	e := mustEngine(t)
	// **/secrets/** from starter policy should deny root-level secrets/ paths
	res, _ := e.Evaluate(policy.ToolCall{ID: "1", Tool: "filesystem.read", Arguments: map[string]interface{}{"path": "secrets/token.txt"}})
	if res.Decision != policy.DecisionDeny {
		t.Fatalf("expected deny for root-level secrets path, got %s: %s", res.Decision, res.Reason)
	}
}

func TestDoubleStarDenyMatchesNestedLevel(t *testing.T) {
	e := mustEngine(t)
	res, _ := e.Evaluate(policy.ToolCall{ID: "1", Tool: "filesystem.read", Arguments: map[string]interface{}{"path": "deep/secrets/token.txt"}})
	if res.Decision != policy.DecisionDeny {
		t.Fatalf("expected deny for nested secrets path, got %s: %s", res.Decision, res.Reason)
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

// TestWindowsAbsolutePathDenied verifies that Windows drive-letter paths are
// treated as absolute and denied (#12).
func TestWindowsAbsolutePathDenied(t *testing.T) {
	e := mustEngine(t)
	res, _ := e.Evaluate(policy.ToolCall{ID: "1", Tool: "filesystem.read", Arguments: map[string]interface{}{"path": `C:\Windows\system32\cmd.exe`}})
	if res.Decision != policy.DecisionDeny {
		t.Fatalf("expected deny for Windows absolute path, got %s: %s", res.Decision, res.Reason)
	}
}

// TestUNCPathDenied verifies that UNC paths (\\server\share) are denied (#12).
func TestUNCPathDenied(t *testing.T) {
	e := mustEngine(t)
	res, _ := e.Evaluate(policy.ToolCall{ID: "1", Tool: "filesystem.read", Arguments: map[string]interface{}{"path": `\\server\share\file`}})
	if res.Decision != policy.DecisionDeny {
		t.Fatalf("expected deny for UNC path, got %s: %s", res.Decision, res.Reason)
	}
}

// TestWindowsTraversalPathDenied verifies that Windows-style traversal paths
// using backslashes are detected and denied (#12).
func TestWindowsTraversalPathDenied(t *testing.T) {
	e := mustEngine(t)
	res, _ := e.Evaluate(policy.ToolCall{ID: "1", Tool: "filesystem.read", Arguments: map[string]interface{}{"path": `..\..\etc\passwd`}})
	if res.Decision != policy.DecisionDeny {
		t.Fatalf("expected deny for Windows traversal path, got %s: %s", res.Decision, res.Reason)
	}
}

// TestWindowsRelativePathAllowed verifies that a Windows-style relative path
// such as src\main.go is treated equivalently to src/main.go (#12).
func TestWindowsRelativePathAllowed(t *testing.T) {
	e := mustEngine(t)
	res, _ := e.Evaluate(policy.ToolCall{ID: "1", Tool: "filesystem.read", Arguments: map[string]interface{}{"path": `src\main.go`}})
	if res.Decision != policy.DecisionAllow {
		t.Fatalf("expected allow for Windows-style relative path, got %s: %s", res.Decision, res.Reason)
	}
}
