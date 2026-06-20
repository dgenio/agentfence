package oplog

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestParseFormat(t *testing.T) {
	tests := []struct {
		in      string
		want    Format
		wantErr bool
	}{
		{"", FormatText, false},
		{"text", FormatText, false},
		{"json", FormatJSON, false},
		{"xml", "", true},
		{"JSON", "", true}, // case-sensitive
	}
	for _, tt := range tests {
		got, err := ParseFormat(tt.in)
		if tt.wantErr {
			if err == nil {
				t.Errorf("ParseFormat(%q) expected error, got nil", tt.in)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseFormat(%q) unexpected error: %v", tt.in, err)
		}
		if got != tt.want {
			t.Errorf("ParseFormat(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestTextHandlerFormat(t *testing.T) {
	var buf bytes.Buffer
	log := New(&buf, FormatText, false)
	log.Warn("audit write failed", "err", "disk full")
	got := buf.String()

	if !strings.HasPrefix(got, "agentfence: warning: audit write failed") {
		t.Errorf("text output missing expected prefix: %q", got)
	}
	if !strings.Contains(got, "err=disk full") {
		t.Errorf("text output missing attribute: %q", got)
	}
	if !strings.HasSuffix(got, "\n") {
		t.Errorf("text output should end with newline: %q", got)
	}
}

func TestTextHandlerErrorPrefix(t *testing.T) {
	var buf bytes.Buffer
	log := New(&buf, FormatText, false)
	log.Error("upstream request failed", "kind", "upstream")
	if !strings.Contains(buf.String(), "error: upstream request failed") {
		t.Errorf("error level should carry an error: prefix: %q", buf.String())
	}
}

func TestJSONHandlerFormat(t *testing.T) {
	var buf bytes.Buffer
	log := New(&buf, FormatJSON, false)
	log.Error("upstream request failed", "kind", "upstream")

	var rec map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &rec); err != nil {
		t.Fatalf("JSON handler did not emit valid JSON: %v\n%s", err, buf.String())
	}
	if rec["msg"] != "upstream request failed" {
		t.Errorf("msg = %v, want %q", rec["msg"], "upstream request failed")
	}
	if rec["kind"] != "upstream" {
		t.Errorf("kind attr = %v, want %q", rec["kind"], "upstream")
	}
	if rec["level"] != "ERROR" {
		t.Errorf("level = %v, want ERROR", rec["level"])
	}
}

func TestDebugSuppressedUnlessEnabled(t *testing.T) {
	var buf bytes.Buffer
	log := New(&buf, FormatText, false)
	log.Debug("forwarded frame", "line", "x")
	if buf.Len() != 0 {
		t.Errorf("debug record should be suppressed when debug=false, got %q", buf.String())
	}

	buf.Reset()
	log = New(&buf, FormatText, true)
	log.Debug("forwarded frame", "line", "x")
	if buf.Len() == 0 {
		t.Errorf("debug record should be emitted when debug=true")
	}
}

func TestNilWriterDiscards(t *testing.T) {
	log := New(nil, FormatJSON, true)
	// Must not panic and must produce no output anywhere.
	log.Error("should be discarded", "k", "v")
}
