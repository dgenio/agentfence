package engine

import (
	"strings"
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

func TestDecisionReasonDescribesMatchKind(t *testing.T) {
	p, err := policy.ParsePolicy([]byte(`version: "0.1"
defaults:
  decision: deny
groups:
  shell-tools:
    - shell.exec
tools:
  filesystem.read:
    decision: allow
  shell-tools:
    decision: ask
  browser.*:
    decision: allow
`))
	if err != nil {
		t.Fatalf("ParsePolicy error: %v", err)
	}
	e, err := New(p)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	tests := []struct {
		name       string
		tool       string
		wantReason string
	}{
		{
			name:       "exact",
			tool:       "filesystem.read",
			wantReason: "tool filesystem.read matched explicit policy rule",
		},
		{
			name:       "group",
			tool:       "shell.exec",
			wantReason: `tool shell.exec matched group rule "shell-tools"`,
		},
		{
			name:       "wildcard",
			tool:       "browser.navigate",
			wantReason: `tool browser.navigate matched wildcard rule "browser.*"`,
		},
		{
			name:       "default",
			tool:       "unknown.tool",
			wantReason: "no rule for unknown.tool; using default decision",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res, _ := e.Evaluate(policy.ToolCall{ID: "1", Tool: tt.tool, Arguments: map[string]interface{}{}})
			if res.Reason != tt.wantReason {
				t.Fatalf("reason = %q, want %q", res.Reason, tt.wantReason)
			}
		})
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

func TestPathSafetyAlwaysApplied(t *testing.T) {
	p, err := policy.ParsePolicy([]byte(`version: "0.1"
defaults:
  decision: deny
tools:
  filesystem.read:
    decision: allow
`))
	if err != nil {
		t.Fatalf("ParsePolicy error: %v", err)
	}
	e, err := New(p)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	tests := []struct {
		name string
		args map[string]interface{}
		want policy.Decision
	}{
		{
			name: "absolute path denied",
			args: map[string]interface{}{"path": "/etc/passwd"},
			want: policy.DecisionDeny,
		},
		{
			name: "parent traversal denied",
			args: map[string]interface{}{"path": "../etc/passwd"},
			want: policy.DecisionDeny,
		},
		{
			name: "UNC path denied",
			args: map[string]interface{}{"path": `\\server\share\secret.txt`},
			want: policy.DecisionDeny,
		},
		{
			name: "safe relative path allowed",
			args: map[string]interface{}{"path": "docs/readme.md"},
			want: policy.DecisionAllow,
		},
		{
			name: "missing path unaffected",
			args: map[string]interface{}{},
			want: policy.DecisionAllow,
		},
		{
			name: "non-string path unaffected",
			args: map[string]interface{}{"path": 12},
			want: policy.DecisionAllow,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res, _ := e.Evaluate(policy.ToolCall{ID: "1", Tool: "filesystem.read", Arguments: tt.args})
			if res.Decision != tt.want {
				t.Fatalf("decision = %s, want %s: %s", res.Decision, tt.want, res.Reason)
			}
		})
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

// ── #21: Wildcard tool name matching & tool groups ────────────────────────────

func TestWildcardSuffixMatch(t *testing.T) {
	p, err := policy.ParsePolicy([]byte(`version: "0.1"
defaults:
  decision: deny
tools:
  filesystem.*:
    decision: allow
`))
	if err != nil {
		t.Fatalf("ParsePolicy error: %v", err)
	}
	e, err := New(p)
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	for _, tool := range []string{"filesystem.read", "filesystem.write", "filesystem.list"} {
		res, _ := e.Evaluate(policy.ToolCall{ID: "1", Tool: tool, Arguments: map[string]interface{}{}})
		if res.Decision != policy.DecisionAllow {
			t.Errorf("expected allow for %s, got %s: %s", tool, res.Decision, res.Reason)
		}
	}
}

func TestExactBeatsWildcard(t *testing.T) {
	p, err := policy.ParsePolicy([]byte(`version: "0.1"
defaults:
  decision: deny
tools:
  filesystem.*:
    decision: ask
  filesystem.read:
    decision: allow
`))
	if err != nil {
		t.Fatalf("ParsePolicy error: %v", err)
	}
	e, err := New(p)
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	res, _ := e.Evaluate(policy.ToolCall{ID: "1", Tool: "filesystem.read", Arguments: map[string]interface{}{}})
	if res.Decision != policy.DecisionAllow {
		t.Fatalf("exact rule should beat wildcard; got %s: %s", res.Decision, res.Reason)
	}
	// Other filesystem.* still hit the wildcard rule.
	res, _ = e.Evaluate(policy.ToolCall{ID: "2", Tool: "filesystem.write", Arguments: map[string]interface{}{}})
	if res.Decision != policy.DecisionAsk {
		t.Fatalf("expected ask for filesystem.write via wildcard, got %s", res.Decision)
	}
}

func TestGroupMatch(t *testing.T) {
	p, err := policy.ParsePolicy([]byte(`version: "0.1"
defaults:
  decision: deny
groups:
  fs-tools:
    - filesystem.read
    - filesystem.write
    - filesystem.*
tools:
  fs-tools:
    decision: ask
`))
	if err != nil {
		t.Fatalf("ParsePolicy error: %v", err)
	}
	e, err := New(p)
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	for _, tool := range []string{"filesystem.read", "filesystem.write", "filesystem.list"} {
		res, _ := e.Evaluate(policy.ToolCall{ID: "1", Tool: tool, Arguments: map[string]interface{}{}})
		if res.Decision != policy.DecisionAsk {
			t.Errorf("expected ask via group for %s, got %s: %s", tool, res.Decision, res.Reason)
		}
	}
}

func TestExactBeatsGroup(t *testing.T) {
	p, err := policy.ParsePolicy([]byte(`version: "0.1"
defaults:
  decision: deny
groups:
  fs-tools:
    - filesystem.*
tools:
  fs-tools:
    decision: ask
  filesystem.read:
    decision: allow
`))
	if err != nil {
		t.Fatalf("ParsePolicy error: %v", err)
	}
	e, err := New(p)
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	res, _ := e.Evaluate(policy.ToolCall{ID: "1", Tool: "filesystem.read", Arguments: map[string]interface{}{}})
	if res.Decision != policy.DecisionAllow {
		t.Fatalf("exact rule should beat group; got %s: %s", res.Decision, res.Reason)
	}
}

func TestGroupBeatsWildcard(t *testing.T) {
	p, err := policy.ParsePolicy([]byte(`version: "0.1"
defaults:
  decision: deny
groups:
  fs-tools:
    - filesystem.*
tools:
  fs-tools:
    decision: ask
  filesystem.*:
    decision: deny
`))
	if err != nil {
		t.Fatalf("ParsePolicy error: %v", err)
	}
	e, err := New(p)
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	res, _ := e.Evaluate(policy.ToolCall{ID: "1", Tool: "filesystem.write", Arguments: map[string]interface{}{}})
	if res.Decision != policy.DecisionAsk {
		t.Fatalf("group rule should beat wildcard key; got %s: %s", res.Decision, res.Reason)
	}
}

// ── #22: Argument value constraints ──────────────────────────────────────────

func TestArgConstraintAllow(t *testing.T) {
	p, err := policy.ParsePolicy([]byte(`version: "0.1"
defaults:
  decision: deny
tools:
  github.create_issue:
    decision: ask
    constraints:
      args:
        repo:
          allow: ["dgenio/*", "myorg/*"]
`))
	if err != nil {
		t.Fatalf("ParsePolicy error: %v", err)
	}
	e, err := New(p)
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	res, _ := e.Evaluate(policy.ToolCall{ID: "1", Tool: "github.create_issue", Arguments: map[string]interface{}{"repo": "dgenio/agentfence"}})
	if res.Decision != policy.DecisionAsk {
		t.Fatalf("expected ask for allowed repo, got %s: %s", res.Decision, res.Reason)
	}
}

func TestArgConstraintDeny(t *testing.T) {
	p, err := policy.ParsePolicy([]byte(`version: "0.1"
defaults:
  decision: deny
tools:
  github.create_issue:
    decision: ask
    constraints:
      args:
        repo:
          allow: ["dgenio/*"]
          deny: ["dgenio/private-*"]
`))
	if err != nil {
		t.Fatalf("ParsePolicy error: %v", err)
	}
	e, err := New(p)
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	res, _ := e.Evaluate(policy.ToolCall{ID: "1", Tool: "github.create_issue", Arguments: map[string]interface{}{"repo": "dgenio/private-api"}})
	if res.Decision != policy.DecisionDeny {
		t.Fatalf("expected deny for private repo, got %s: %s", res.Decision, res.Reason)
	}
}

func TestArgConstraintMissingField(t *testing.T) {
	p, err := policy.ParsePolicy([]byte(`version: "0.1"
defaults:
  decision: deny
tools:
  github.create_issue:
    decision: ask
    constraints:
      args:
        repo:
          allow: ["dgenio/*"]
`))
	if err != nil {
		t.Fatalf("ParsePolicy error: %v", err)
	}
	e, err := New(p)
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	res, _ := e.Evaluate(policy.ToolCall{ID: "1", Tool: "github.create_issue", Arguments: map[string]interface{}{}})
	if res.Decision != policy.DecisionDeny {
		t.Fatalf("expected deny for missing constrained arg, got %s: %s", res.Decision, res.Reason)
	}
}

// ── #23: URL constraints ──────────────────────────────────────────────────────

func TestURLConstraintAllow(t *testing.T) {
	e := mustURLEngine(t)
	res, _ := e.Evaluate(policy.ToolCall{ID: "1", Tool: "browser.navigate", Arguments: map[string]interface{}{"url": "https://docs.github.com/en"}})
	if res.Decision != policy.DecisionAllow {
		t.Fatalf("expected allow for docs.github.com, got %s: %s", res.Decision, res.Reason)
	}
}

func TestURLConstraintDeniedScheme(t *testing.T) {
	e := mustURLEngine(t)
	res, _ := e.Evaluate(policy.ToolCall{ID: "1", Tool: "browser.navigate", Arguments: map[string]interface{}{"url": "http://evil.example.com"}})
	if res.Decision != policy.DecisionDeny {
		t.Fatalf("expected deny for plain http, got %s: %s", res.Decision, res.Reason)
	}
}

func TestURLConstraintFileSchemeAlwaysDenied(t *testing.T) {
	e := mustURLEngine(t)
	res, _ := e.Evaluate(policy.ToolCall{ID: "1", Tool: "browser.navigate", Arguments: map[string]interface{}{"url": "file:///etc/passwd"}})
	if res.Decision != policy.DecisionDeny {
		t.Fatalf("expected deny for file:// URL, got %s: %s", res.Decision, res.Reason)
	}
}

func TestURLConstraintBareIPAlwaysDenied(t *testing.T) {
	e := mustURLEngine(t)
	res, _ := e.Evaluate(policy.ToolCall{ID: "1", Tool: "browser.navigate", Arguments: map[string]interface{}{"url": "https://192.168.1.1/admin"}})
	if res.Decision != policy.DecisionDeny {
		t.Fatalf("expected deny for bare IP, got %s: %s", res.Decision, res.Reason)
	}
}

func TestURLConstraintInvalidURL(t *testing.T) {
	e := mustURLEngine(t)
	res, _ := e.Evaluate(policy.ToolCall{ID: "1", Tool: "browser.navigate", Arguments: map[string]interface{}{"url": "not a url"}})
	if res.Decision != policy.DecisionDeny {
		t.Fatalf("expected deny for invalid URL, got %s: %s", res.Decision, res.Reason)
	}
}

func TestURLConstraintMissingArg(t *testing.T) {
	e := mustURLEngine(t)
	res, _ := e.Evaluate(policy.ToolCall{ID: "1", Tool: "browser.navigate", Arguments: map[string]interface{}{}})
	if res.Decision != policy.DecisionDeny {
		t.Fatalf("expected deny for missing url arg, got %s: %s", res.Decision, res.Reason)
	}
}

func mustURLEngine(t *testing.T) *Engine {
	t.Helper()
	p, err := policy.ParsePolicy([]byte(`version: "0.1"
defaults:
  decision: deny
tools:
  browser.navigate:
    decision: allow
    constraints:
      urls:
        allow:
          - "https://docs.github.com/**"
          - "https://*.company.com/**"
        deny:
          - "http://**"
`))
	if err != nil {
		t.Fatalf("ParsePolicy error: %v", err)
	}
	e, err := New(p)
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	return e
}

// ── #24: Shell command constraints ───────────────────────────────────────────

func TestCommandConstraintAllowExecutable(t *testing.T) {
	e := mustCommandEngine(t)
	res, _ := e.Evaluate(policy.ToolCall{ID: "1", Tool: "shell.exec", Arguments: map[string]interface{}{"command": "git status"}})
	if res.Decision != policy.DecisionAsk {
		t.Fatalf("expected ask for allowed executable 'git', got %s: %s", res.Decision, res.Reason)
	}
}

func TestCommandConstraintDeniedPattern(t *testing.T) {
	e := mustCommandEngine(t)
	res, _ := e.Evaluate(policy.ToolCall{ID: "1", Tool: "shell.exec", Arguments: map[string]interface{}{"command": "rm -rf /"}})
	if res.Decision != policy.DecisionDeny {
		t.Fatalf("expected deny for 'rm -rf /', got %s: %s", res.Decision, res.Reason)
	}
}

func TestCommandConstraintForbiddenExecutable(t *testing.T) {
	e := mustCommandEngine(t)
	res, _ := e.Evaluate(policy.ToolCall{ID: "1", Tool: "shell.exec", Arguments: map[string]interface{}{"command": "curl https://example.com"}})
	if res.Decision != policy.DecisionDeny {
		t.Fatalf("expected deny for non-allowed executable 'curl', got %s: %s", res.Decision, res.Reason)
	}
}

func TestCommandConstraintMissingArg(t *testing.T) {
	e := mustCommandEngine(t)
	res, _ := e.Evaluate(policy.ToolCall{ID: "1", Tool: "shell.exec", Arguments: map[string]interface{}{}})
	if res.Decision != policy.DecisionDeny {
		t.Fatalf("expected deny for missing command arg, got %s: %s", res.Decision, res.Reason)
	}
}

func mustCommandEngine(t *testing.T) *Engine {
	t.Helper()
	p, err := policy.ParsePolicy([]byte(`version: "0.1"
defaults:
  decision: deny
tools:
  shell.exec:
    decision: ask
    constraints:
      command:
        allow_executables: ["git", "go", "make"]
        deny_patterns: ["rm -rf*", "curl * | bash", "wget * | sh"]
`))
	if err != nil {
		t.Fatalf("ParsePolicy error: %v", err)
	}
	e, err := New(p)
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	return e
}

// ── #19: TraceEvaluate ────────────────────────────────────────────────────────

func TestTraceEvaluateExplicitRule(t *testing.T) {
	e := mustEngine(t)
	result, trace := e.TraceEvaluate(policy.ToolCall{ID: "1", Tool: "github.delete_repo", Arguments: map[string]interface{}{}})
	if result.Decision != policy.DecisionDeny {
		t.Fatalf("expected deny, got %s", result.Decision)
	}
	if len(trace) == 0 {
		t.Fatal("expected non-empty trace")
	}
}

func TestTraceEvaluateDefaultDecision(t *testing.T) {
	e := mustEngine(t)
	result, trace := e.TraceEvaluate(policy.ToolCall{ID: "1", Tool: "unknown.tool", Arguments: map[string]interface{}{}})
	if result.Decision != policy.DecisionDeny {
		t.Fatalf("expected deny (default), got %s", result.Decision)
	}
	if len(trace) == 0 {
		t.Fatal("expected non-empty trace for default decision")
	}
	found := false
	for _, step := range trace {
		if strings.Contains(step, "default") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected trace to mention 'default'; got: %v", trace)
	}
}

func TestTraceEvaluatePathDeny(t *testing.T) {
	e := mustEngine(t)
	result, trace := e.TraceEvaluate(policy.ToolCall{ID: "1", Tool: "filesystem.write", Arguments: map[string]interface{}{"path": ".env"}})
	if result.Decision != policy.DecisionDeny {
		t.Fatalf("expected deny for .env path, got %s", result.Decision)
	}
	if len(trace) == 0 {
		t.Fatal("expected non-empty trace")
	}
}

// memoryWriteEngine builds an engine from a policy with a memory.write rule
// that enforces the standard memory_write constraints used by the issue #43
// fixtures.
func memoryWriteEngine(t *testing.T) *Engine {
	t.Helper()
	p, err := policy.ParsePolicy([]byte(`version: "0.1"
defaults:
  decision: deny
tools:
  memory.write:
    decision: ask
    constraints:
      memory_write:
        max_scope: project
        max_sensitivity: medium
        max_bytes: 1024
redaction:
  enabled: true
  patterns:
    - name: generic_secret_assignment
      regex: "(?i)(api_key|token|secret|password)\\s*[:=]\\s*[^\\s]+"
    - name: openai_api_key
      regex: "sk-[A-Za-z0-9_-]{20,}"
`))
	if err != nil {
		t.Fatalf("ParsePolicy error: %v", err)
	}
	e, err := New(p)
	if err != nil {
		t.Fatalf("New error: %v", err)
	}
	return e
}

// TestMemoryWriteSafePreferenceAllowed covers the issue #43 "safe preference
// write" fixture: short, low-sensitivity payload within scope → ask (the rule's
// declared decision).
func TestMemoryWriteSafePreferenceAllowed(t *testing.T) {
	e := memoryWriteEngine(t)
	res, event := e.Evaluate(policy.ToolCall{
		ID:   "mem-1",
		Tool: "memory.write",
		Arguments: map[string]interface{}{
			"scope": "project",
			"value": "user prefers dark mode",
		},
	})
	if res.Decision != policy.DecisionAsk {
		t.Fatalf("expected ask, got %s (%s)", res.Decision, res.Reason)
	}
	if event.MemoryWrite == nil {
		t.Fatal("expected audit MemoryWrite summary, got nil")
	}
	if event.MemoryWrite.Scope != "project" {
		t.Errorf("scope: got %q want project", event.MemoryWrite.Scope)
	}
	if event.MemoryWrite.Sensitivity != "low" {
		t.Errorf("sensitivity: got %q want low", event.MemoryWrite.Sensitivity)
	}
	if event.MemoryWrite.Field != "value" {
		t.Errorf("field: got %q want value", event.MemoryWrite.Field)
	}
	if event.MemoryWrite.SizeBytes != len("user prefers dark mode") {
		t.Errorf("size_bytes: got %d want %d", event.MemoryWrite.SizeBytes, len("user prefers dark mode"))
	}
	if event.MemoryWrite.ContentFingerprint == "" {
		t.Error("expected non-empty content_fingerprint")
	}
	if len(event.MemoryWrite.PatternsMatched) != 0 {
		t.Errorf("expected no pattern matches; got %v", event.MemoryWrite.PatternsMatched)
	}
}

// TestMemoryWriteSecretPayloadDenied covers the "unsafe secret write" fixture:
// payload matches a redaction pattern → auto-classify high → exceeds
// max_sensitivity=medium → deny.
func TestMemoryWriteSecretPayloadDenied(t *testing.T) {
	e := memoryWriteEngine(t)
	res, event := e.Evaluate(policy.ToolCall{
		ID:   "mem-2",
		Tool: "memory.write",
		Arguments: map[string]interface{}{
			"scope": "project",
			"value": "OPENAI_API_KEY=sk-demo-very-long-secret-value-1234",
		},
	})
	if res.Decision != policy.DecisionDeny {
		t.Fatalf("expected deny, got %s (%s)", res.Decision, res.Reason)
	}
	if !strings.Contains(res.Reason, "sensitivity") {
		t.Errorf("expected sensitivity-based reason, got: %s", res.Reason)
	}
	if event.MemoryWrite == nil {
		t.Fatal("expected audit MemoryWrite summary even on deny")
	}
	if event.MemoryWrite.Sensitivity != "high" {
		t.Errorf("sensitivity: got %q want high", event.MemoryWrite.Sensitivity)
	}
	if len(event.MemoryWrite.PatternsMatched) == 0 {
		t.Error("expected at least one pattern match on secret-like payload")
	}
	// Critical: the raw payload must NEVER appear in the summary.
	if strings.Contains(event.MemoryWrite.ContentFingerprint, "sk-demo") {
		t.Errorf("content_fingerprint must not leak payload bytes, got %q", event.MemoryWrite.ContentFingerprint)
	}
}

// TestMemoryWriteSecretPayloadDeniedWhenRedactionDisabled verifies memory-write
// classification still inspects configured redaction patterns when audit
// redaction itself is disabled.
func TestMemoryWriteSecretPayloadDeniedWhenRedactionDisabled(t *testing.T) {
	p, err := policy.ParsePolicy([]byte(`version: "0.1"
defaults:
  decision: deny
tools:
  memory.write:
    decision: ask
    constraints:
      memory_write:
        max_sensitivity: medium
redaction:
  enabled: false
  patterns:
    - name: openai_api_key
      regex: "sk-[A-Za-z0-9_-]{20,}"
audit:
  include_redacted_arguments: true
`))
	if err != nil {
		t.Fatalf("ParsePolicy error: %v", err)
	}
	e, err := New(p)
	if err != nil {
		t.Fatalf("New error: %v", err)
	}
	res, event := e.Evaluate(policy.ToolCall{
		ID:   "mem-disabled-redaction",
		Tool: "memory.write",
		Arguments: map[string]interface{}{
			"value": "sk-demo-very-long-secret-value-1234",
		},
	})
	if res.Decision != policy.DecisionDeny {
		t.Fatalf("expected deny, got %s (%s)", res.Decision, res.Reason)
	}
	if event.MemoryWrite == nil {
		t.Fatal("expected audit MemoryWrite summary even on deny")
	}
	if event.MemoryWrite.Sensitivity != "high" {
		t.Errorf("sensitivity: got %q want high", event.MemoryWrite.Sensitivity)
	}
	if len(event.MemoryWrite.PatternsMatched) != 1 || event.MemoryWrite.PatternsMatched[0] != "openai_api_key" {
		t.Errorf("patterns_matched: got %v want [openai_api_key]", event.MemoryWrite.PatternsMatched)
	}
	if got, ok := event.Arguments["value"].(string); !ok || got != "sk-demo-very-long-secret-value-1234" {
		t.Errorf("redaction disabled should leave event arguments unchanged, got %#v", event.Arguments["value"])
	}
}

// TestMemoryWriteScopeTooBroad covers the "questionable durable assumption"
// fixture: payload is harmless but scope=global exceeds max_scope=project.
func TestMemoryWriteScopeTooBroad(t *testing.T) {
	e := memoryWriteEngine(t)
	res, _ := e.Evaluate(policy.ToolCall{
		ID:   "mem-3",
		Tool: "memory.write",
		Arguments: map[string]interface{}{
			"scope": "global",
			"value": "team standup is at 10am",
		},
	})
	if res.Decision != policy.DecisionDeny {
		t.Fatalf("expected deny, got %s (%s)", res.Decision, res.Reason)
	}
	if !strings.Contains(res.Reason, "scope") {
		t.Errorf("expected scope-based reason, got: %s", res.Reason)
	}
}

// TestMemoryWriteOversize covers a payload that exceeds max_bytes.
func TestMemoryWriteOversize(t *testing.T) {
	e := memoryWriteEngine(t)
	big := strings.Repeat("x", 1025)
	res, _ := e.Evaluate(policy.ToolCall{
		ID:   "mem-4",
		Tool: "memory.write",
		Arguments: map[string]interface{}{
			"scope": "project",
			"value": big,
		},
	})
	if res.Decision != policy.DecisionDeny {
		t.Fatalf("expected deny, got %s (%s)", res.Decision, res.Reason)
	}
	if !strings.Contains(res.Reason, "bytes") {
		t.Errorf("expected size-based reason, got: %s", res.Reason)
	}
}

// TestMemoryWriteMissingPayload covers the call-without-payload deny path.
func TestMemoryWriteMissingPayload(t *testing.T) {
	e := memoryWriteEngine(t)
	res, _ := e.Evaluate(policy.ToolCall{
		ID:   "mem-5",
		Tool: "memory.write",
		Arguments: map[string]interface{}{
			"scope": "project",
		},
	})
	if res.Decision != policy.DecisionDeny {
		t.Fatalf("expected deny, got %s (%s)", res.Decision, res.Reason)
	}
	if !strings.Contains(res.Reason, "payload") {
		t.Errorf("expected payload-based reason, got: %s", res.Reason)
	}
}

// TestMemoryWriteContentFallback verifies the "content" payload field is used
// when "value" is absent (default payload field list).
func TestMemoryWriteContentFallback(t *testing.T) {
	e := memoryWriteEngine(t)
	res, event := e.Evaluate(policy.ToolCall{
		ID:   "mem-6",
		Tool: "memory.write",
		Arguments: map[string]interface{}{
			"content": "small note",
		},
	})
	if res.Decision != policy.DecisionAsk {
		t.Fatalf("expected ask, got %s (%s)", res.Decision, res.Reason)
	}
	if event.MemoryWrite == nil {
		t.Fatal("expected MemoryWrite summary")
	}
	if event.MemoryWrite.Field != "content" {
		t.Errorf("expected field=content, got %q", event.MemoryWrite.Field)
	}
}

// TestMemoryWriteExplicitSensitivityWins verifies that an explicit higher
// sensitivity argument is honoured when the redactor would have classified
// the payload lower.
func TestMemoryWriteExplicitSensitivityWins(t *testing.T) {
	e := memoryWriteEngine(t)
	res, _ := e.Evaluate(policy.ToolCall{
		ID:   "mem-7",
		Tool: "memory.write",
		Arguments: map[string]interface{}{
			"scope":       "project",
			"sensitivity": "high",
			"value":       "harmless looking string",
		},
	})
	if res.Decision != policy.DecisionDeny {
		t.Fatalf("explicit high sensitivity should be honoured; got %s (%s)", res.Decision, res.Reason)
	}
}

// TestMemoryWriteInvalidSensitivityDenied verifies malformed sensitivity
// declarations fail closed when max_sensitivity is configured.
func TestMemoryWriteInvalidSensitivityDenied(t *testing.T) {
	e := memoryWriteEngine(t)
	res, _ := e.Evaluate(policy.ToolCall{
		ID:   "mem-invalid-sensitivity",
		Tool: "memory.write",
		Arguments: map[string]interface{}{
			"scope":       "project",
			"sensitivity": "extreme",
			"value":       "harmless looking string",
		},
	})
	if res.Decision != policy.DecisionDeny {
		t.Fatalf("invalid sensitivity should be denied; got %s (%s)", res.Decision, res.Reason)
	}
	if !strings.Contains(res.Reason, "sensitivity") {
		t.Errorf("expected sensitivity-based reason, got: %s", res.Reason)
	}
}

// TestMemoryWriteNoSummaryWhenConstraintAbsent verifies the MemoryWrite
// summary is nil for rules that don't opt in.
func TestMemoryWriteNoSummaryWhenConstraintAbsent(t *testing.T) {
	e := mustEngine(t)
	_, event := e.Evaluate(policy.ToolCall{
		ID:        "1",
		Tool:      "filesystem.read",
		Arguments: map[string]interface{}{"path": "README.md"},
	})
	if event.MemoryWrite != nil {
		t.Errorf("expected MemoryWrite=nil for rule without memory_write constraint, got %+v", event.MemoryWrite)
	}
}
