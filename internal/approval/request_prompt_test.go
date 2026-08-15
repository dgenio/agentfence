package approval

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/dgenio/agentfence/internal/policy"
)

func TestBoundRequestPromptEscapesControlCharactersInLabels(t *testing.T) {
	callID := "call-1\nFAKE: approved\x1b[31m"
	tool := "safe.tool\napprove? (y/N): y"
	request := approvalRequestFixture(t, policy.ToolCall{
		ID:        callID,
		Tool:      tool,
		Arguments: map[string]interface{}{"n": json.Number("1")},
	}, policy.RedactionConfig{})

	prompt := request.Prompt()
	if strings.Contains(prompt, callID) || strings.Contains(prompt, tool) {
		t.Fatal("prompt included raw control-character-bearing label")
	}
	if strings.Count(prompt, "\napprove? (y/N): ") != 1 {
		t.Fatalf("prompt contains spoofable approval lines: %q", prompt)
	}
	if !strings.Contains(prompt, `\nFAKE: approved\u001b[31m`) {
		t.Fatalf("call id was not JSON escaped in prompt: %q", prompt)
	}
	if !strings.Contains(prompt, `safe.tool\napprove? (y/N): y`) {
		t.Fatalf("tool name was not JSON escaped in prompt: %q", prompt)
	}
}

func TestBoundRequestPromptBoundsOversizedLabels(t *testing.T) {
	largeCallID := strings.Repeat("c", MaxLabelDisplayBytes*2)
	largeTool := strings.Repeat("t", MaxLabelDisplayBytes*2)
	request := approvalRequestFixture(t, policy.ToolCall{
		ID:        largeCallID,
		Tool:      largeTool,
		Arguments: map[string]interface{}{},
	}, policy.RedactionConfig{})

	prompt := request.Prompt()
	if strings.Contains(prompt, strings.Repeat("c", 64)) || strings.Contains(prompt, strings.Repeat("t", 64)) {
		t.Fatal("prompt included raw oversized call/tool labels")
	}
	if !strings.Contains(prompt, "call id exceeds 256-byte display limit") {
		t.Fatalf("prompt missing bounded call-id summary: %q", prompt)
	}
	if !strings.Contains(prompt, "tool name exceeds 256-byte display limit") {
		t.Fatalf("prompt missing bounded tool-name summary: %q", prompt)
	}
	if !strings.Contains(prompt, request.ActionDigest()) || !strings.Contains(prompt, request.BindingDigest()) {
		t.Fatal("bounded label display lost exact action/binding evidence")
	}
}
