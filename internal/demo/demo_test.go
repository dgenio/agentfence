package demo

import (
	"bytes"
	"strings"
	"testing"
)

func TestRunProducesExpectedDecisions(t *testing.T) {
	buf := &bytes.Buffer{}
	if err := Run(buf); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	output := buf.String()

	expected := []string{
		"call_001 filesystem.read -> allow",
		"call_002 filesystem.write -> deny",
		"call_003 github.create_issue -> ask",
		"call_004 github.delete_repo -> deny",
	}
	for _, exp := range expected {
		if !strings.Contains(output, exp) {
			t.Errorf("expected output to contain %q, got:\n%s", exp, output)
		}
	}
}
