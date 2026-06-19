package engine

import (
	"strings"
	"testing"

	"github.com/dgenio/agentfence/internal/policy"
)

// conformancePolicy mirrors the worked examples in docs/policy-language.md for
// every constraint family, so the documented "Behavior:" bullets are pinned
// against the real engine. If the docs and engine drift apart, the matching
// subtest below fails. Keep this policy in sync with the doc's examples.
const conformancePolicy = `version: "0.1"
defaults:
  decision: deny
tools:
  filesystem.write:
    decision: allow
    constraints:
      paths:
        allow:
          - "./src/**"
        deny:
          - ".env"
          - "**/secrets/**"
  github.create_issue:
    decision: allow
    constraints:
      args:
        repo:
          allow:
            - "dgenio/*"
            - "myorg/*"
          deny:
            - "dgenio/private-*"
  browser.navigate:
    decision: allow
    constraints:
      urls:
        allow:
          - "https://docs.github.com/**"
          - "https://*.company.com/**"
        deny:
          - "http://**"
  shell.exec:
    decision: allow
    constraints:
      command:
        allow_executables:
          - "git"
          - "go"
          - "make"
        deny_patterns:
          - "rm -rf*"
          - "curl * | bash"
  memory.write:
    decision: allow
    constraints:
      memory_write:
        max_scope: project
        max_sensitivity: medium
        max_bytes: 1024
redaction:
  enabled: true
  patterns:
    - name: openai_api_key
      regex: "sk-[A-Za-z0-9_-]{20,}"
`

func TestPolicyLanguageConformance(t *testing.T) {
	e := mustEngineFromYAML(t, conformancePolicy)

	// wantReason, when non-empty, is asserted as a substring of the engine's
	// Reason. It pins not just the decision but *why* the engine reached it, so
	// a regression that returns the right decision for the wrong reason (e.g. a
	// deny that stops matching its intended pattern but still denies via a
	// fallback) is caught. Substrings are used to stay robust to wording tweaks.
	tests := []struct {
		family     string
		name       string
		tool       string
		args       map[string]interface{}
		want       policy.Decision
		wantReason string
	}{
		// Path constraints (docs/policy-language.md → "Path constraints").
		{"paths", "deny pattern always denies", "filesystem.write", map[string]interface{}{"path": ".env"}, policy.DecisionDeny, `denied by pattern ".env"`},
		{"paths", "nested deny via doublestar", "filesystem.write", map[string]interface{}{"path": "src/secrets/key.pem"}, policy.DecisionDeny, `denied by pattern "**/secrets/**"`},
		{"paths", "allowed when matching allow", "filesystem.write", map[string]interface{}{"path": "src/app/main.go"}, policy.DecisionAllow, ""},
		{"paths", "not in allow list denied", "filesystem.write", map[string]interface{}{"path": "docs/readme.md"}, policy.DecisionDeny, "not in allowed paths"},
		{"paths", "absolute always denied", "filesystem.write", map[string]interface{}{"path": "/etc/passwd"}, policy.DecisionDeny, "is absolute"},

		// Argument value constraints (docs → "Argument value constraints").
		{"args", "deny precedence over allow", "github.create_issue", map[string]interface{}{"repo": "dgenio/private-secrets"}, policy.DecisionDeny, `denied by pattern "dgenio/private-*"`},
		{"args", "allowed when matching allow", "github.create_issue", map[string]interface{}{"repo": "dgenio/agentfence"}, policy.DecisionAllow, ""},
		{"args", "not in allow list denied", "github.create_issue", map[string]interface{}{"repo": "other/thing"}, policy.DecisionDeny, "not in allowed values"},
		{"args", "missing constrained field denied", "github.create_issue", map[string]interface{}{}, policy.DecisionDeny, `missing required argument "repo"`},

		// URL constraints (docs → "URL constraints").
		{"urls", "matched allow", "browser.navigate", map[string]interface{}{"url": "https://docs.github.com/en/rest"}, policy.DecisionAllow, ""},
		{"urls", "not in allow denied", "browser.navigate", map[string]interface{}{"url": "https://evil.example.com/x"}, policy.DecisionDeny, "not in allowed URLs"},
		{"urls", "deny pattern", "browser.navigate", map[string]interface{}{"url": "http://docs.github.com/x"}, policy.DecisionDeny, `denied by pattern "http://**"`},
		{"urls", "file scheme always denied", "browser.navigate", map[string]interface{}{"url": "file:///etc/passwd"}, policy.DecisionDeny, "is not a valid URL"},
		{"urls", "bare IP always denied", "browser.navigate", map[string]interface{}{"url": "https://192.168.1.1/admin"}, policy.DecisionDeny, "bare IP address"},
		{"urls", "missing url denied", "browser.navigate", map[string]interface{}{}, policy.DecisionDeny, "missing required url argument"},

		// Shell command constraints (docs → "Shell command constraints").
		// Note: "rm" is rejected because it is not in allow_executables — that
		// check fires before deny_patterns, so the reason names the executable
		// allowlist, not the "rm -rf*" deny pattern.
		{"command", "executable not allowed", "shell.exec", map[string]interface{}{"command": "rm -rf /"}, policy.DecisionDeny, `executable "rm" is not in the allowed executables`},
		{"command", "allowed executable", "shell.exec", map[string]interface{}{"command": "git status"}, policy.DecisionAllow, ""},
		{"command", "forbidden executable denied", "shell.exec", map[string]interface{}{"command": "python evil.py"}, policy.DecisionDeny, `executable "python" is not in the allowed executables`},
		{"command", "missing command denied", "shell.exec", map[string]interface{}{}, policy.DecisionDeny, "missing required command argument"},

		// Memory-write constraints (docs → "Durable memory-write constraints").
		{"memory_write", "scope too broad denied", "memory.write", map[string]interface{}{"scope": "global", "value": "ok"}, policy.DecisionDeny, `scope "global" exceeds max allowed`},
		{"memory_write", "high sensitivity denied", "memory.write", map[string]interface{}{"value": "sk-abcdefghijklmnopqrstuvwxyz"}, policy.DecisionDeny, `sensitivity "high" exceeds max allowed`},
		{"memory_write", "oversize denied", "memory.write", map[string]interface{}{"value": strings.Repeat("a", 2000)}, policy.DecisionDeny, ""},
		{"memory_write", "missing payload denied", "memory.write", map[string]interface{}{}, policy.DecisionDeny, "non-empty payload"},
		{"memory_write", "safe small write allowed", "memory.write", map[string]interface{}{"value": "a benign note"}, policy.DecisionAllow, ""},
	}

	for _, tt := range tests {
		t.Run(tt.family+"/"+tt.name, func(t *testing.T) {
			res, _ := e.Evaluate(policy.ToolCall{ID: "1", Tool: tt.tool, Arguments: tt.args})
			if res.Decision != tt.want {
				t.Fatalf("%s/%s: decision = %s, want %s: %s", tt.family, tt.name, res.Decision, tt.want, res.Reason)
			}
			if tt.wantReason != "" && !strings.Contains(res.Reason, tt.wantReason) {
				t.Fatalf("%s/%s: reason = %q, want it to contain %q", tt.family, tt.name, res.Reason, tt.wantReason)
			}
		})
	}
}
