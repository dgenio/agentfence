package audit

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/dgenio/agentfence/internal/policy"
)

func TestWriteJSONL(t *testing.T) {
	buf := &bytes.Buffer{}
	w := NewWriter(buf)
	e := Event{
		Timestamp: "2026-01-01T00:00:00Z",
		CallID:    "call_1",
		Tool:      "filesystem.read",
		Decision:  policy.DecisionAllow,
		Reason:    "allowed",
		Arguments: map[string]interface{}{"path": "README.md"},
	}
	if err := w.Write(e); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	line := strings.TrimSpace(buf.String())
	var out map[string]interface{}
	if err := json.Unmarshal([]byte(line), &out); err != nil {
		t.Fatalf("invalid JSON output: %v", err)
	}
	if out["decision"] != string(policy.DecisionAllow) {
		t.Fatalf("expected decision allow, got %v", out["decision"])
	}
}
