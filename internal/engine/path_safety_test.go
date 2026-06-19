package engine

import (
	"testing"

	"github.com/dgenio/agentfence/internal/policy"
)

// pathSafetyEngine returns an engine whose filesystem.read rule allows
// everything with no explicit path constraints, so a test exercises the
// always-on path-safety pre-check rather than allow/deny glob lists.
func pathSafetyEngine(t *testing.T) *Engine {
	t.Helper()
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
	return e
}

// TestPathSafetyWindowsStyleInputs pins the path-safety pre-check against
// Windows-style inputs on every host the binaries target (#175). The engine
// normalizes backslashes and rejects drive-qualified, UNC, traversal, and
// Unix-absolute paths host-independently, so the same input is denied whether
// the test runs on Linux, macOS, or Windows.
func TestPathSafetyWindowsStyleInputs(t *testing.T) {
	e := pathSafetyEngine(t)

	tests := []struct {
		name string
		path string
		want policy.Decision
	}{
		{"drive absolute backslash", `C:\Windows\system32\cmd.exe`, policy.DecisionDeny},
		{"drive absolute forward", "C:/Windows/system32", policy.DecisionDeny},
		{"drive absolute lowercase", "c:/temp/x", policy.DecisionDeny},
		{"bare drive root", "C:", policy.DecisionDeny},
		{"drive relative", `C:foo\bar.txt`, policy.DecisionDeny},
		{"unc backslash", `\\server\share\secret.txt`, policy.DecisionDeny},
		{"unc forward", "//server/share/secret.txt", policy.DecisionDeny},
		{"backslash traversal", `..\..\Windows\win.ini`, policy.DecisionDeny},
		{"mixed-separator traversal", `..\../etc/passwd`, policy.DecisionDeny},
		{"unix absolute on any host", "/etc/passwd", policy.DecisionDeny},
		{"windows relative allowed", `src\main.go`, policy.DecisionAllow},
		{"windows nested relative allowed", `docs\guide\intro.md`, policy.DecisionAllow},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res, _ := e.Evaluate(policy.ToolCall{
				ID:        "1",
				Tool:      "filesystem.read",
				Arguments: map[string]interface{}{"path": tt.path},
			})
			if res.Decision != tt.want {
				t.Fatalf("path %q: decision = %s, want %s: %s", tt.path, res.Decision, tt.want, res.Reason)
			}
		})
	}
}

// TestPathSafetyIsLexicalOnly documents and pins two non-guarantees of the
// path-safety check (#170): it operates purely on the path string and never
// touches the filesystem, so it does not resolve symlinks; and its glob/deny
// matching is case-sensitive, so a case-variant of a denied path is not
// caught. Operators must not rely on this check for symlink- or case-based
// containment. See docs/threat-model.md ("Path-safety guarantees").
func TestPathSafetyIsLexicalOnly(t *testing.T) {
	t.Run("does not resolve symlinks", func(t *testing.T) {
		e := pathSafetyEngine(t)
		// A lexically-safe relative path is allowed even though a path
		// component could be a symlink pointing outside the project root.
		// The engine performs no filesystem resolution, so this is allowed
		// regardless of what exists on disk.
		res, _ := e.Evaluate(policy.ToolCall{
			ID:        "1",
			Tool:      "filesystem.read",
			Arguments: map[string]interface{}{"path": "linked/secret.txt"},
		})
		if res.Decision != policy.DecisionAllow {
			t.Fatalf("expected allow for lexically-safe path, got %s: %s", res.Decision, res.Reason)
		}
	})

	t.Run("deny matching is case-sensitive", func(t *testing.T) {
		// The starter policy denies ".env" and "**/secrets/**".
		e := mustEngine(t)

		cases := []struct {
			path string
			want policy.Decision
		}{
			{".env", policy.DecisionDeny},
			{".ENV", policy.DecisionAllow}, // case-variant escapes the deny
			{"secrets/token.txt", policy.DecisionDeny},
			{"SECRETS/token.txt", policy.DecisionAllow}, // case-variant escapes the deny
		}
		for _, c := range cases {
			res, _ := e.Evaluate(policy.ToolCall{
				ID:        "1",
				Tool:      "filesystem.read",
				Arguments: map[string]interface{}{"path": c.path},
			})
			if res.Decision != c.want {
				t.Fatalf("path %q: decision = %s, want %s: %s", c.path, res.Decision, c.want, res.Reason)
			}
		}
	})
}
