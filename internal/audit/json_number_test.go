package audit

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/dgenio/agentfence/internal/policy"
)

func TestWriterPreservesJSONNumberArguments(t *testing.T) {
	var out bytes.Buffer
	w := NewWriterOptions(&out, Options{SessionID: "test-session"})

	event := NewEvent(
		policy.ToolCall{ID: "c1", Tool: "example.run"},
		policy.EvaluationResult{Decision: policy.DecisionAllow, Reason: "allowed"},
		map[string]interface{}{
			"large":  json.Number("9007199254740993"),
			"number": json.Number("1"),
			"string": "1",
		},
		true,
	)
	if err := w.Write(event); err != nil {
		t.Fatalf("Write() error = %v", err)
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(bytes.TrimSpace(out.Bytes()), &raw); err != nil {
		t.Fatalf("audit JSON invalid: %v", err)
	}
	var args map[string]json.RawMessage
	if err := json.Unmarshal(raw["arguments"], &args); err != nil {
		t.Fatalf("arguments JSON invalid: %v", err)
	}

	if got := string(args["large"]); got != "9007199254740993" {
		t.Fatalf("large argument = %s, want exact JSON number", got)
	}
	if got := string(args["number"]); got != "1" {
		t.Fatalf("number argument = %s, want JSON number 1", got)
	}
	if got := string(args["string"]); got != `"1"` {
		t.Fatalf("string argument = %s, want quoted JSON string", got)
	}
}
