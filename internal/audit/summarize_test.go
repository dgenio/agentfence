package audit

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
	"testing"

	"github.com/dgenio/agentfence/internal/policy"
)

// errAfterWriter fails once cumulative writes exceed limit bytes, simulating a
// broken pipe partway through output. limit=0 fails on the first write.
type errAfterWriter struct {
	limit   int
	written int
}

func (w *errAfterWriter) Write(p []byte) (int, error) {
	w.written += len(p)
	if w.written > w.limit {
		return 0, io.ErrClosedPipe
	}
	return len(p), nil
}

// writeLog serialises events through a non-chaining Writer so the input to
// Summarize matches the on-wire layout that operators see in real audit logs.
func writeLog(t *testing.T, events []Event) []byte {
	t.Helper()
	buf := &bytes.Buffer{}
	w := NewWriterOptions(buf, Options{SessionID: "test-session"})
	for _, e := range events {
		if err := w.Write(e); err != nil {
			t.Fatalf("Write() error = %v", err)
		}
	}
	return buf.Bytes()
}

func TestSummarizeEmpty(t *testing.T) {
	s, err := Summarize(strings.NewReader(""), 0)
	if err != nil {
		t.Fatalf("Summarize(empty) error = %v", err)
	}
	if s.Total != 0 || s.Malformed != 0 {
		t.Fatalf("expected zero totals; got Total=%d Malformed=%d", s.Total, s.Malformed)
	}
	if len(s.TopTools) != 0 {
		t.Fatalf("expected empty TopTools, got %d", len(s.TopTools))
	}
}

func TestSummarizeCountsByDecisionAndTool(t *testing.T) {
	log := writeLog(t, []Event{
		{Tool: "filesystem.read", Decision: policy.DecisionAllow, Reason: "explicit"},
		{Tool: "filesystem.read", Decision: policy.DecisionAllow, Reason: "explicit"},
		{Tool: "github.delete_repo", Decision: policy.DecisionDeny, Reason: "destructive"},
		{Tool: "github.delete_repo", Decision: policy.DecisionDeny, Reason: "destructive"},
		{Tool: "github.delete_repo", Decision: policy.DecisionDeny, Reason: "destructive"},
		{Tool: "github.create_issue", Decision: policy.DecisionAsk, Reason: "ask"},
	})

	s, err := Summarize(bytes.NewReader(log), 0)
	if err != nil {
		t.Fatalf("Summarize() error = %v", err)
	}
	if s.Total != 6 {
		t.Fatalf("Total = %d, want 6", s.Total)
	}
	if s.ByDecision["allow"] != 2 {
		t.Errorf("allow = %d, want 2", s.ByDecision["allow"])
	}
	if s.ByDecision["deny"] != 3 {
		t.Errorf("deny = %d, want 3", s.ByDecision["deny"])
	}
	if s.ByDecision["ask"] != 1 {
		t.Errorf("ask = %d, want 1", s.ByDecision["ask"])
	}

	if len(s.TopTools) != 3 {
		t.Fatalf("TopTools length = %d, want 3", len(s.TopTools))
	}
	if s.TopTools[0].Tool != "github.delete_repo" || s.TopTools[0].Count != 3 {
		t.Errorf("TopTools[0] = %+v, want github.delete_repo/3", s.TopTools[0])
	}
	if s.TopTools[1].Tool != "filesystem.read" || s.TopTools[1].Count != 2 {
		t.Errorf("TopTools[1] = %+v, want filesystem.read/2", s.TopTools[1])
	}

	if len(s.TopDeniedTools) != 1 || s.TopDeniedTools[0].Tool != "github.delete_repo" {
		t.Errorf("TopDeniedTools = %+v, want [github.delete_repo]", s.TopDeniedTools)
	}
	if len(s.TopAllowedTools) != 1 || s.TopAllowedTools[0].Tool != "filesystem.read" {
		t.Errorf("TopAllowedTools = %+v, want [filesystem.read]", s.TopAllowedTools)
	}
}

func TestSummarizeTopNBounded(t *testing.T) {
	events := make([]Event, 0, 15)
	for i := 0; i < 15; i++ {
		events = append(events, Event{
			Tool:     "tool." + string(rune('a'+i)),
			Decision: policy.DecisionAllow,
			Reason:   "r",
		})
	}
	log := writeLog(t, events)
	s, err := Summarize(bytes.NewReader(log), 5)
	if err != nil {
		t.Fatalf("Summarize() error = %v", err)
	}
	if len(s.TopTools) != 5 {
		t.Fatalf("TopTools length = %d, want 5 (topN bound)", len(s.TopTools))
	}
}

func TestSummarizeMalformedLinesCounted(t *testing.T) {
	good := `{"schema_version":"1","session_id":"s","seq":1,"timestamp":"t","call_id":"c","tool":"filesystem.read","decision":"allow","reason":"r"}`
	bad := `{this is not json`
	blank := ``
	input := good + "\n" + bad + "\n" + blank + "\n" + good + "\n"

	s, err := Summarize(strings.NewReader(input), 0)
	if err != nil {
		t.Fatalf("Summarize(mixed) error = %v", err)
	}
	if s.Total != 2 {
		t.Errorf("Total = %d, want 2", s.Total)
	}
	if s.Malformed != 1 {
		t.Errorf("Malformed = %d, want 1", s.Malformed)
	}
}

func TestSummarizeFinalLineWithoutNewline(t *testing.T) {
	// JSONL files emitted by other tools may omit the trailing newline.
	// Summarize must still process the final event.
	good := `{"schema_version":"1","session_id":"s","seq":1,"timestamp":"t","call_id":"c","tool":"x","decision":"deny","reason":"r"}`
	s, err := Summarize(strings.NewReader(good), 0)
	if err != nil {
		t.Fatalf("Summarize() error = %v", err)
	}
	if s.Total != 1 {
		t.Errorf("Total = %d, want 1", s.Total)
	}
}

func TestSummarizeReasonAggregation(t *testing.T) {
	// Reasons must aggregate per (decision, reason) — the same reason text
	// under a different decision is a different row.
	log := writeLog(t, []Event{
		{Tool: "a", Decision: policy.DecisionAllow, Reason: "matched rule"},
		{Tool: "b", Decision: policy.DecisionAllow, Reason: "matched rule"},
		{Tool: "c", Decision: policy.DecisionDeny, Reason: "matched rule"},
	})
	s, err := Summarize(bytes.NewReader(log), 0)
	if err != nil {
		t.Fatalf("Summarize() error = %v", err)
	}
	if len(s.TopReasons) != 2 {
		t.Fatalf("TopReasons = %+v, want 2 distinct rows", s.TopReasons)
	}
	if s.TopReasons[0].Count != 2 || s.TopReasons[0].Decision != "allow" {
		t.Errorf("TopReasons[0] = %+v, want allow/2", s.TopReasons[0])
	}
	if s.TopReasons[1].Count != 1 || s.TopReasons[1].Decision != "deny" {
		t.Errorf("TopReasons[1] = %+v, want deny/1", s.TopReasons[1])
	}
}

func TestSummarizeSchemaVersionAggregation(t *testing.T) {
	mixed := `{"schema_version":"1","session_id":"s","seq":1,"timestamp":"t","call_id":"c","tool":"x","decision":"allow","reason":"r"}
{"schema_version":"2","session_id":"s","seq":2,"timestamp":"t","call_id":"c","tool":"x","decision":"allow","reason":"r"}
{"schema_version":"2","session_id":"s","seq":3,"timestamp":"t","call_id":"c","tool":"x","decision":"allow","reason":"r"}
`
	s, err := Summarize(strings.NewReader(mixed), 0)
	if err != nil {
		t.Fatalf("Summarize() error = %v", err)
	}
	if s.BySchemaVersion["1"] != 1 || s.BySchemaVersion["2"] != 2 {
		t.Errorf("BySchemaVersion = %+v, want {1:1, 2:2}", s.BySchemaVersion)
	}
}

func TestSummarizeFormatTextDeterministic(t *testing.T) {
	log := writeLog(t, []Event{
		{Tool: "filesystem.read", Decision: policy.DecisionAllow, Reason: "explicit"},
		{Tool: "github.delete_repo", Decision: policy.DecisionDeny, Reason: "destructive"},
	})
	s, err := Summarize(bytes.NewReader(log), 0)
	if err != nil {
		t.Fatalf("Summarize() error = %v", err)
	}
	buf := &bytes.Buffer{}
	if err := s.FormatText(buf); err != nil {
		t.Fatalf("FormatText() error = %v", err)
	}
	out := buf.String()
	wantSnippets := []string{
		"total events:   2",
		"by decision:    allow=1 deny=1 ask=0",
		"Top tools",
		"filesystem.read",
		"github.delete_repo",
		"Top denied tools",
		"Top allowed tools",
	}
	for _, w := range wantSnippets {
		if !strings.Contains(out, w) {
			t.Errorf("FormatText output missing %q; got:\n%s", w, out)
		}
	}
}

func TestSummarizeJSONShape(t *testing.T) {
	log := writeLog(t, []Event{
		{Tool: "a", Decision: policy.DecisionAllow, Reason: "r"},
	})
	s, err := Summarize(bytes.NewReader(log), 0)
	if err != nil {
		t.Fatalf("Summarize() error = %v", err)
	}
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatalf("json.Marshal(Summary) error = %v", err)
	}
	// Stable, automation-friendly field names.
	for _, f := range []string{`"total"`, `"by_decision"`, `"top_tools"`, `"top_reasons"`, `"malformed"`} {
		if !bytes.Contains(b, []byte(f)) {
			t.Errorf("JSON output missing field %s; got %s", f, b)
		}
	}
}

func TestSummarizeFormatTextPropagatesWriteError(t *testing.T) {
	log := writeLog(t, []Event{
		{Tool: "filesystem.read", Decision: policy.DecisionAllow, Reason: "explicit"},
		{Tool: "github.delete_repo", Decision: policy.DecisionDeny, Reason: "destructive"},
	})
	s, err := Summarize(bytes.NewReader(log), 0)
	if err != nil {
		t.Fatalf("Summarize() error = %v", err)
	}

	// limit 0 forces the very first write to fail.
	if err := s.FormatText(&errAfterWriter{limit: 0}); err == nil {
		t.Error("FormatText() returned nil despite a writer that fails immediately")
	}
	// A mid-stream failure (after the header has been written) must also surface.
	if err := s.FormatText(&errAfterWriter{limit: 30}); err == nil {
		t.Error("FormatText() returned nil despite a mid-stream write failure")
	}
}

func TestSummarizeEmptyJSONObjectCountedMalformed(t *testing.T) {
	// A syntactically valid JSON object that carries neither a decision nor a
	// tool is not a real audit event: it must be counted as malformed, not as
	// a Total event, and must not create an empty-decision bucket.
	input := `{}
{"schema_version":"1","session_id":"s","seq":1,"timestamp":"t","call_id":"c","tool":"x","decision":"allow","reason":"r"}
`
	s, err := Summarize(strings.NewReader(input), 0)
	if err != nil {
		t.Fatalf("Summarize() error = %v", err)
	}
	if s.Total != 1 {
		t.Errorf("Total = %d, want 1", s.Total)
	}
	if s.Malformed != 1 {
		t.Errorf("Malformed = %d, want 1", s.Malformed)
	}
	if _, ok := s.ByDecision[""]; ok {
		t.Errorf("ByDecision must not contain an empty-decision bucket; got %+v", s.ByDecision)
	}
}
