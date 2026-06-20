// Package oplog provides AgentFence's structured operational logger.
//
// Operational logs are the diagnostics AgentFence writes to stderr — warnings,
// upstream/proxy errors, approval-IO failures, debug frame dumps. They are a
// distinct stream from the audit log (decision records on a file/sink) and from
// the decision output (stdout). This package wraps log/slog so those
// diagnostics can be emitted either as the default human-readable text or as
// machine-parseable JSON for a log pipeline, selected with --log-format.
//
// The text format is the default and is intended to read like the plain stderr
// output AgentFence produced before structured logging existed; the JSON format
// emits one slog record per line.
package oplog

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"strings"
)

// Format selects the operational log encoding.
type Format string

const (
	// FormatText is the default human-readable encoding.
	FormatText Format = "text"
	// FormatJSON emits one structured JSON record per line.
	FormatJSON Format = "json"
)

// ParseFormat validates a --log-format value, returning an error for anything
// other than "text" or "json". An empty string defaults to text.
func ParseFormat(s string) (Format, error) {
	switch s {
	case "", string(FormatText):
		return FormatText, nil
	case string(FormatJSON):
		return FormatJSON, nil
	default:
		return "", fmt.Errorf("invalid log format %q: want \"text\" or \"json\"", s)
	}
}

// New returns an *slog.Logger writing to w in the given format. When debug is
// false, debug-level records (e.g. forwarded-frame dumps) are dropped. A nil w
// disables logging.
//
// The text handler is deliberately minimal: it omits slog's timestamp and level
// prefix on info records so the default output stays close to AgentFence's
// historical plain-stderr diagnostics, while still attaching structured
// attributes. The JSON handler emits the full slog record per line.
func New(w io.Writer, format Format, debug bool) *slog.Logger {
	if w == nil {
		return slog.New(discardHandler{})
	}
	level := slog.LevelInfo
	if debug {
		level = slog.LevelDebug
	}
	switch format {
	case FormatJSON:
		return slog.New(slog.NewJSONHandler(w, &slog.HandlerOptions{Level: level}))
	default:
		return slog.New(newTextHandler(w, level))
	}
}

// textHandler renders operational records in AgentFence's historical style:
// "agentfence: <message> [key=value ...]" with no timestamp or level banner for
// info/warn, and a "warning: " / "error: " prefix for higher levels so they
// remain scannable.
type textHandler struct {
	w     io.Writer
	level slog.Level
	attrs []slog.Attr
	group string
}

func newTextHandler(w io.Writer, level slog.Level) *textHandler {
	return &textHandler{w: w, level: level}
}

func (h *textHandler) Enabled(_ context.Context, l slog.Level) bool { return l >= h.level }

func (h *textHandler) Handle(_ context.Context, r slog.Record) error {
	var b strings.Builder
	b.WriteString("agentfence: ")
	switch {
	case r.Level >= slog.LevelError:
		b.WriteString("error: ")
	case r.Level >= slog.LevelWarn:
		b.WriteString("warning: ")
	}
	b.WriteString(r.Message)

	writeAttr := func(a slog.Attr) {
		if a.Equal(slog.Attr{}) {
			return
		}
		key := a.Key
		if h.group != "" {
			key = h.group + "." + key
		}
		fmt.Fprintf(&b, " %s=%v", key, a.Value.Any())
	}
	for _, a := range h.attrs {
		writeAttr(a)
	}
	r.Attrs(func(a slog.Attr) bool {
		writeAttr(a)
		return true
	})
	b.WriteByte('\n')
	_, err := io.WriteString(h.w, b.String())
	return err
}

func (h *textHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	clone := *h
	clone.attrs = append(append([]slog.Attr{}, h.attrs...), attrs...)
	return &clone
}

func (h *textHandler) WithGroup(name string) slog.Handler {
	clone := *h
	if name != "" {
		clone.group = name
	}
	return &clone
}

// discardHandler drops every record. Used for a nil destination.
type discardHandler struct{}

func (discardHandler) Enabled(context.Context, slog.Level) bool  { return false }
func (discardHandler) Handle(context.Context, slog.Record) error { return nil }
func (discardHandler) WithAttrs([]slog.Attr) slog.Handler        { return discardHandler{} }
func (discardHandler) WithGroup(string) slog.Handler             { return discardHandler{} }
