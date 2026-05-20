package audit_test

// Issue #41: redaction regression tests for serialized audit output.
//
// These tests are intentionally in the external `audit_test` package so they
// exercise the public surface the way real callers do: build a Redactor +
// Engine, evaluate a tool call, and assert that the JSONL audit line never
// contains any raw fake secret value.

import (
	"bytes"
	"strings"
	"testing"

	"github.com/dgenio/agentfence/internal/audit"
	"github.com/dgenio/agentfence/internal/engine"
	"github.com/dgenio/agentfence/internal/policy"
)

// allFakeSecrets are clearly synthetic values. Each one matches at least one
// pattern in redactionPatterns below, so they must never appear raw in audit
// output once the patterns are applied.
var allFakeSecrets = []string{
	"sk-demo_secret_NEVERLEAK_API_KEY_VALUE",            // openai_api_key
	"ghp_fake_token_for_tests_NEVERLEAK",                // github_token
	"AKIA_FAKE_AWS_KEY_NEVERLEAK_TEST",                  // aws_access_key
	"postgres://user:fakePW_NEVERLEAK_TEST@db.example.com/x", // database_url
	"Bearer fake_jwt_NEVERLEAK_for_tests",               // bearer_token
	"password=hunter2_NEVERLEAK_SECRET_VAL",             // generic_secret_assignment
}

// redactionPatterns mirrors the patterns used in examples/policy.yaml plus a
// couple of broader catch-all rules. Each test asserts that ALL allFakeSecrets
// strings are absent from the serialised line, not just the ones the specific
// pattern was designed for.
var redactionPatterns = []policy.RedactionPattern{
	{Name: "openai_api_key", Regex: `sk-[A-Za-z0-9_-]{20,}`},
	{Name: "github_token", Regex: `gh[pousr]_[A-Za-z0-9_]{20,}`},
	{Name: "aws_access_key", Regex: `AKIA[A-Z0-9_]{12,}`},
	{Name: "database_url", Regex: `postgres://[^\s]+`},
	{Name: "bearer_token", Regex: `(?i)bearer\s+[A-Za-z0-9._-]+`},
	{Name: "generic_secret_assignment", Regex: `(?i)(api_key|token|secret|password)\s*[:=]\s*[^\s]+`},
}

// buildEngine constructs an Engine wired up with the test redaction patterns
// and a single tool rule producing the requested decision.
func buildEngine(t *testing.T, toolName string, decision policy.Decision) *engine.Engine {
	t.Helper()
	p := policy.Policy{
		Defaults: policy.Defaults{Decision: policy.DecisionDeny},
		Tools: map[string]policy.Rule{
			toolName: {Decision: decision},
		},
		Redaction: policy.RedactionConfig{
			Enabled:  true,
			Patterns: redactionPatterns,
		},
		Audit: policy.AuditConfig{
			Format:                   "jsonl",
			IncludeRedactedArguments: true,
		},
	}
	eng, err := engine.New(p)
	if err != nil {
		t.Fatalf("engine.New: %v", err)
	}
	return eng
}

// runAndCollect evaluates `call` and returns the serialised JSONL line written
// to the audit Writer.
func runAndCollect(t *testing.T, eng *engine.Engine, call policy.ToolCall, opts audit.Options) string {
	t.Helper()
	buf := &bytes.Buffer{}
	aw := audit.NewWriterOptions(buf, opts)
	_, event := eng.Evaluate(call)
	if err := aw.Write(event); err != nil {
		t.Fatalf("audit.Writer.Write: %v", err)
	}
	return buf.String()
}

// assertNoRawSecret fails the test if any of allFakeSecrets appears verbatim in
// the serialised audit output. Substring matching catches both top-level leaks
// and accidental leaks inside JSON-escaped strings.
func assertNoRawSecret(t *testing.T, serialised, context string) {
	t.Helper()
	for _, secret := range allFakeSecrets {
		if strings.Contains(serialised, secret) {
			t.Errorf("[%s] audit output contained raw fake secret %q\nfull output: %s",
				context, secret, serialised)
		}
	}
}

func TestRedactionTopLevelAllow(t *testing.T) {
	eng := buildEngine(t, "filesystem.write", policy.DecisionAllow)
	call := policy.ToolCall{
		ID:   "c1",
		Tool: "filesystem.write",
		Arguments: map[string]interface{}{
			"path":    ".env",
			"content": "OPENAI_API_KEY=" + allFakeSecrets[0],
		},
	}
	out := runAndCollect(t, eng, call, audit.Options{})
	assertNoRawSecret(t, out, "top-level/allow")
}

func TestRedactionTopLevelDeny(t *testing.T) {
	eng := buildEngine(t, "filesystem.write", policy.DecisionDeny)
	call := policy.ToolCall{
		ID:   "c1",
		Tool: "filesystem.write",
		Arguments: map[string]interface{}{
			"path":  ".env",
			"token": allFakeSecrets[1], // ghp_...
		},
	}
	out := runAndCollect(t, eng, call, audit.Options{})
	assertNoRawSecret(t, out, "top-level/deny")
}

func TestRedactionTopLevelAsk(t *testing.T) {
	eng := buildEngine(t, "github.create_issue", policy.DecisionAsk)
	call := policy.ToolCall{
		ID:   "c1",
		Tool: "github.create_issue",
		Arguments: map[string]interface{}{
			"body": "please use my token " + allFakeSecrets[1],
		},
	}
	out := runAndCollect(t, eng, call, audit.Options{})
	assertNoRawSecret(t, out, "top-level/ask")
}

func TestRedactionNestedObject(t *testing.T) {
	eng := buildEngine(t, "http.request", policy.DecisionAllow)
	call := policy.ToolCall{
		ID:   "c1",
		Tool: "http.request",
		Arguments: map[string]interface{}{
			"url": "https://example.com/api",
			"headers": map[string]interface{}{
				"Authorization": allFakeSecrets[4], // Bearer ...
				"X-DB-URL":      allFakeSecrets[3], // postgres://...
			},
		},
	}
	out := runAndCollect(t, eng, call, audit.Options{})
	assertNoRawSecret(t, out, "nested-object")
}

func TestRedactionArrayValues(t *testing.T) {
	eng := buildEngine(t, "vault.set", policy.DecisionAllow)
	call := policy.ToolCall{
		ID:   "c1",
		Tool: "vault.set",
		Arguments: map[string]interface{}{
			"secrets": []interface{}{
				allFakeSecrets[2], // AKIA...
				"non-secret-value",
				map[string]interface{}{"k": allFakeSecrets[5]}, // password=hunter2_...
			},
		},
	}
	out := runAndCollect(t, eng, call, audit.Options{})
	assertNoRawSecret(t, out, "array-values")
}

func TestRedactionWithTamperEvidentChain(t *testing.T) {
	// Issue #41 + #33 interaction: when the chain hash includes the arguments
	// payload, redaction must still be effective.
	eng := buildEngine(t, "filesystem.write", policy.DecisionDeny)
	call := policy.ToolCall{
		ID:   "c1",
		Tool: "filesystem.write",
		Arguments: map[string]interface{}{
			"content": "API_KEY=" + allFakeSecrets[0],
		},
	}
	out := runAndCollect(t, eng, call, audit.Options{TamperEvident: true})
	assertNoRawSecret(t, out, "tamper-evident/deny")
}

func TestParseErrorEventDoesNotLogArguments(t *testing.T) {
	// audit.NewErrorEvent is used for malformed JSONL lines. Even though the
	// caller passes the raw error message in, the audit Event itself MUST NOT
	// carry the raw input as arguments (its Arguments field stays nil).
	buf := &bytes.Buffer{}
	w := audit.NewWriter(buf)
	if err := w.Write(audit.NewErrorEvent(42, "unexpected token "+allFakeSecrets[0])); err != nil {
		t.Fatalf("Write: %v", err)
	}
	// The reason itself MAY contain the offending input (it came from us, not
	// from a redactable channel), but Arguments must not be populated.
	if bytes.Contains(buf.Bytes(), []byte(`"arguments"`)) {
		t.Errorf("NewErrorEvent leaked arguments field: %s", buf.String())
	}
}
