package policy

import "testing"

func TestParsePolicy(t *testing.T) {
	p, err := ParsePolicy([]byte(StarterPolicyYAML))
	if err != nil {
		t.Fatalf("ParsePolicy() error = %v", err)
	}
	if p.Defaults.Decision != DecisionDeny {
		t.Fatalf("expected default deny, got %s", p.Defaults.Decision)
	}
	if p.Tools["github.create_issue"].Decision != DecisionAsk {
		t.Fatalf("expected ask for github.create_issue")
	}
}

func TestParseToolCall(t *testing.T) {
	call, err := ParseToolCall([]byte(`{"id":"call_1","tool":"filesystem.read","arguments":{"path":"README.md"}}`))
	if err != nil {
		t.Fatalf("ParseToolCall() error = %v", err)
	}
	if call.Tool != "filesystem.read" {
		t.Fatalf("expected filesystem.read, got %s", call.Tool)
	}
}
