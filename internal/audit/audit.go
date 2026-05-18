package audit

import (
	"encoding/json"
	"io"
	"time"

	"github.com/dgenio/agentfence/internal/policy"
)

type Event struct {
	Timestamp string                 `json:"timestamp"`
	CallID    string                 `json:"call_id"`
	Tool      string                 `json:"tool"`
	Decision  policy.Decision        `json:"decision"`
	Reason    string                 `json:"reason"`
	Arguments map[string]interface{} `json:"arguments,omitempty"`
}

type Writer struct {
	w io.Writer
}

func NewWriter(w io.Writer) *Writer {
	return &Writer{w: w}
}

func NewEvent(call policy.ToolCall, result policy.EvaluationResult, redacted map[string]interface{}, includeArgs bool) Event {
	e := Event{
		Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
		CallID:    call.ID,
		Tool:      call.Tool,
		Decision:  result.Decision,
		Reason:    result.Reason,
	}
	if includeArgs {
		e.Arguments = redacted
	}
	return e
}

func (w *Writer) Write(event Event) error {
	b, err := json.Marshal(event)
	if err != nil {
		return err
	}
	if _, err := w.w.Write(append(b, '\n')); err != nil {
		return err
	}
	return nil
}
