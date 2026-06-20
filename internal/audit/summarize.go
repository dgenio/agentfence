package audit

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"sort"

	"github.com/dgenio/agentfence/internal/policy"
)

// Summary aggregates audit events into counts useful for operators reviewing
// agent activity. It is the result of Summarize and is stable for both
// human-readable and JSON output.
type Summary struct {
	// Total is the number of audit events that parsed successfully. Malformed
	// lines are reported via Malformed and do not advance Total.
	Total int `json:"total"`

	// ByDecision counts events by policy.Decision (allow / deny / ask). Keys
	// are stringified decisions so the JSON output is plain and predictable.
	ByDecision map[string]int `json:"by_decision"`

	// BySchemaVersion counts events grouped by their schema_version field.
	// Helpful for spotting mixed-version logs after a schema bump.
	BySchemaVersion map[string]int `json:"by_schema_version,omitempty"`

	// ByReasonCode counts events grouped by their stable reason_code field
	// (see policy.ReasonCode). Unlike TopReasons, which groups free-text
	// reasons that may reword over time, this grouping is robust to wording
	// changes and is the preferred key for alerting. Events without a
	// reason_code (pre-taxonomy logs) are not counted here.
	ByReasonCode map[string]int `json:"by_reason_code,omitempty"`

	// TopTools lists the most common tool names. The slice is bounded by the
	// caller-supplied top-N and sorted by Count descending, Tool ascending
	// for deterministic ties.
	TopTools []ToolCount `json:"top_tools"`

	// TopReasons lists the most common (Decision, Reason) pairs. Same
	// ordering rules as TopTools.
	TopReasons []ReasonCount `json:"top_reasons"`

	// TopDeniedTools and TopAllowedTools are tool counts restricted to a
	// single decision class, which is what reviewers usually want first.
	TopDeniedTools  []ToolCount `json:"top_denied_tools"`
	TopAllowedTools []ToolCount `json:"top_allowed_tools"`

	// Malformed counts JSONL lines that could not be interpreted as an audit
	// event: lines that fail to parse as JSON, plus valid JSON that carries
	// neither a decision nor a tool (e.g. "{}"). Lines containing only
	// whitespace are not counted as malformed.
	Malformed int `json:"malformed"`
}

// ToolCount is a single tool-name aggregation row.
type ToolCount struct {
	Tool  string `json:"tool"`
	Count int    `json:"count"`
}

// ReasonCount is a single (decision, reason) aggregation row.
type ReasonCount struct {
	Decision string `json:"decision"`
	Reason   string `json:"reason"`
	Count    int    `json:"count"`
}

// Summarize reads JSONL audit events from r and returns aggregated counts.
//
// topN bounds the size of the TopTools, TopReasons, TopDeniedTools, and
// TopAllowedTools slices. A non-positive topN defaults to 10. Pass a very
// large topN to retrieve every distinct value.
//
// Malformed lines are counted, not fatal — Summarize never returns an error
// for malformed JSON. It only returns an error if r itself fails to read.
func Summarize(r io.Reader, topN int) (Summary, error) {
	if topN <= 0 {
		topN = 10
	}

	s := Summary{
		ByDecision:      map[string]int{},
		BySchemaVersion: map[string]int{},
		ByReasonCode:    map[string]int{},
	}
	toolCounts := map[string]int{}
	deniedTools := map[string]int{}
	allowedTools := map[string]int{}
	reasonCounts := map[struct{ decision, reason string }]int{}

	br := bufio.NewReader(r)
	for {
		line, readErr := br.ReadBytes('\n')
		line = bytes.TrimRight(line, "\r\n")

		if len(bytes.TrimSpace(line)) == 0 {
			if readErr != nil {
				if readErr == io.EOF {
					break
				}
				return Summary{}, fmt.Errorf("audit: read input: %w", readErr)
			}
			continue
		}

		var e Event
		if err := json.Unmarshal(line, &e); err != nil || (e.Decision == "" && e.Tool == "") {
			// Malformed JSON, or valid JSON that isn't an audit event (no
			// decision and no tool, e.g. "{}") — either way it's not a real
			// event, so count it as malformed rather than inflating Total.
			s.Malformed++
		} else {
			s.Total++
			s.ByDecision[string(e.Decision)]++
			if e.SchemaVersion != "" {
				s.BySchemaVersion[e.SchemaVersion]++
			}
			if e.ReasonCode != "" {
				s.ByReasonCode[string(e.ReasonCode)]++
			}
			if e.Tool != "" {
				toolCounts[e.Tool]++
				switch e.Decision {
				case policy.DecisionDeny:
					deniedTools[e.Tool]++
				case policy.DecisionAllow:
					allowedTools[e.Tool]++
				}
			}
			rk := struct{ decision, reason string }{decision: string(e.Decision), reason: e.Reason}
			reasonCounts[rk]++
		}

		if readErr != nil {
			if readErr == io.EOF {
				break
			}
			return Summary{}, fmt.Errorf("audit: read input: %w", readErr)
		}
	}

	s.TopTools = topToolCounts(toolCounts, topN)
	s.TopDeniedTools = topToolCounts(deniedTools, topN)
	s.TopAllowedTools = topToolCounts(allowedTools, topN)
	s.TopReasons = topReasonCounts(reasonCounts, topN)
	return s, nil
}

func topToolCounts(m map[string]int, topN int) []ToolCount {
	out := make([]ToolCount, 0, len(m))
	for tool, count := range m {
		out = append(out, ToolCount{Tool: tool, Count: count})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Tool < out[j].Tool
	})
	if len(out) > topN {
		out = out[:topN]
	}
	return out
}

func topReasonCounts(m map[struct{ decision, reason string }]int, topN int) []ReasonCount {
	out := make([]ReasonCount, 0, len(m))
	for k, count := range m {
		out = append(out, ReasonCount{Decision: k.decision, Reason: k.reason, Count: count})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		if out[i].Decision != out[j].Decision {
			return out[i].Decision < out[j].Decision
		}
		return out[i].Reason < out[j].Reason
	})
	if len(out) > topN {
		out = out[:topN]
	}
	return out
}

// FormatText renders s as a compact human-readable report on w.
//
// Output is stable across runs given identical inputs and is intended for
// terminal consumption. Use json.Marshal on Summary for automation.
func (s Summary) FormatText(w io.Writer) error {
	ew := &errWriter{w: w}
	ew.printf("Audit summary\n")
	ew.printf("  total events:   %d\n", s.Total)
	ew.printf("  malformed:      %d\n", s.Malformed)
	ew.printf("  by decision:    allow=%d deny=%d ask=%d\n",
		s.ByDecision[string(policy.DecisionAllow)],
		s.ByDecision[string(policy.DecisionDeny)],
		s.ByDecision[string(policy.DecisionAsk)])

	if len(s.BySchemaVersion) > 0 {
		ew.printf("  schema versions:")
		versions := sortedKeys(s.BySchemaVersion)
		for _, v := range versions {
			ew.printf(" %s=%d", v, s.BySchemaVersion[v])
		}
		ew.printf("\n")
	}

	if len(s.ByReasonCode) > 0 {
		ew.printf("\nBy reason code:\n")
		for _, code := range sortedKeys(s.ByReasonCode) {
			ew.printf("  %5d  %s\n", s.ByReasonCode[code], code)
		}
	}

	writeToolSection(ew, "Top tools (all decisions)", s.TopTools)
	writeToolSection(ew, "Top denied tools", s.TopDeniedTools)
	writeToolSection(ew, "Top allowed tools", s.TopAllowedTools)
	writeReasonSection(ew, "Top reasons", s.TopReasons)
	return ew.err
}

// errWriter accumulates the first write error so FormatText can render its
// whole report with simple printf calls and still surface a broken-pipe or
// short-write failure to the caller. Once err is set, subsequent writes are
// skipped.
type errWriter struct {
	w   io.Writer
	err error
}

func (ew *errWriter) printf(format string, args ...interface{}) {
	if ew.err != nil {
		return
	}
	_, ew.err = fmt.Fprintf(ew.w, format, args...)
}

func writeToolSection(ew *errWriter, title string, rows []ToolCount) {
	if len(rows) == 0 {
		return
	}
	ew.printf("\n%s:\n", title)
	for _, r := range rows {
		ew.printf("  %5d  %s\n", r.Count, r.Tool)
	}
}

func writeReasonSection(ew *errWriter, title string, rows []ReasonCount) {
	if len(rows) == 0 {
		return
	}
	ew.printf("\n%s:\n", title)
	for _, r := range rows {
		ew.printf("  %5d  [%s] %s\n", r.Count, r.Decision, r.Reason)
	}
}

func sortedKeys(m map[string]int) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
