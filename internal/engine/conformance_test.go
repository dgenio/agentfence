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

	tests := []struct {
		family string
		name   string
		tool   string
		args   map[string]interface{}
		want   policy.Decision
	}{
		// Path constraints (docs/policy-language.md → "Path constraints").
		{"paths", "deny pattern always denies", "filesystem.write", map[string]interface{}{"path": ".env"}, policy.DecisionDeny},
		{"paths", "nested deny via doublestar", "filesystem.write", map[string]interface{}{"path": "src/secrets/key.pem"}, policy.DecisionDeny},
		{"paths", "allowed when matching allow", "filesystem.write", map[string]interface{}{"path": "src/app/main.go"}, policy.DecisionAllow},
		{"paths", "not in allow list denied", "filesystem.write", map[string]interface{}{"path": "docs/readme.md"}, policy.DecisionDeny},
		{"paths", "absolute always denied", "filesystem.write", map[string]interface{}{"path": "/etc/passwd"}, policy.DecisionDeny},

		// Argument value constraints (docs → "Argument value constraints").
		{"args", "deny precedence over allow", "github.create_issue", map[string]interface{}{"repo": "dgenio/private-secrets"}, policy.DecisionDeny},
		{"args", "allowed when matching allow", "github.create_issue", map[string]interface{}{"repo": "dgenio/agentfence"}, policy.DecisionAllow},
		{"args", "not in allow list denied", "github.create_issue", map[string]interface{}{"repo": "other/thing"}, policy.DecisionDeny},
		{"args", "missing constrained field denied", "github.create_issue", map[string]interface{}{}, policy.DecisionDeny},

		// URL constraints (docs → "URL constraints").
		{"urls", "matched allow", "browser.navigate", map[string]interface{}{"url": "https://docs.github.com/en/rest"}, policy.DecisionAllow},
		{"urls", "not in allow denied", "browser.navigate", map[string]interface{}{"url": "https://evil.example.com/x"}, policy.DecisionDeny},
		{"urls", "deny pattern", "browser.navigate", map[string]interface{}{"url": "http://docs.github.com/x"}, policy.DecisionDeny},
		{"urls", "file scheme always denied", "browser.navigate", map[string]interface{}{"url": "file:///etc/passwd"}, policy.DecisionDeny},
		{"urls", "bare IP always denied", "browser.navigate", map[string]interface{}{"url": "https://192.168.1.1/admin"}, policy.DecisionDeny},
		{"urls", "missing url denied", "browser.navigate", map[string]interface{}{}, policy.DecisionDeny},

		// Shell command constraints (docs → "Shell command constraints").
		{"command", "deny pattern precedence", "shell.exec", map[string]interface{}{"command": "rm -rf /"}, policy.DecisionDeny},
		{"command", "allowed executable", "shell.exec", map[string]interface{}{"command": "git status"}, policy.DecisionAllow},
		{"command", "forbidden executable denied", "shell.exec", map[string]interface{}{"command": "python evil.py"}, policy.DecisionDeny},
		{"command", "missing command denied", "shell.exec", map[string]interface{}{}, policy.DecisionDeny},

		// Memory-write constraints (docs → "Durable memory-write constraints").
		{"memory_write", "scope too broad denied", "memory.write", map[string]interface{}{"scope": "global", "value": "ok"}, policy.DecisionDeny},
		{"memory_write", "high sensitivity denied", "memory.write", map[string]interface{}{"value": "sk-abcdefghijklmnopqrstuvwxyz"}, policy.DecisionDeny},
		{"memory_write", "oversize denied", "memory.write", map[string]interface{}{"value": strings.Repeat("a", 2000)}, policy.DecisionDeny},
		{"memory_write", "missing payload denied", "memory.write", map[string]interface{}{}, policy.DecisionDeny},
		{"memory_write", "safe small write allowed", "memory.write", map[string]interface{}{"value": "a benign note"}, policy.DecisionAllow},
	}

	for _, tt := range tests {
		t.Run(tt.family+"/"+tt.name, func(t *testing.T) {
			res, _ := e.Evaluate(policy.ToolCall{ID: "1", Tool: tt.tool, Arguments: tt.args})
			if res.Decision != tt.want {
				t.Fatalf("%s/%s: decision = %s, want %s: %s", tt.family, tt.name, res.Decision, tt.want, res.Reason)
			}
		})
	}
}
