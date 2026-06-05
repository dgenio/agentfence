// Package taint implements session-scoped data-flow (taint) tracking used to
// detect the confused-deputy pattern in MCP tool use: an untrusted tool result
// (a fetched web page, a file's contents, an issue body) carries injected
// instructions that drive a *later* tool call whose arguments are individually
// "allowed" by the static policy. A per-call allowlist cannot see that a path,
// URL, or command was lifted from earlier untrusted output; a Tracker can.
//
// The model is deliberately simple and explainable, not a full information-flow
// analysis: values observed in tool outputs are remembered for the session, and
// a later call argument is flagged when it is a verbatim slice of (or contains)
// a remembered value. This reduces — it does not eliminate — confused-deputy
// risk; see docs/threat-model.md for the honest scope and limitations.
package taint

import (
	"sort"
	"strings"
	"sync"
)

// Tracker remembers fragments seen in untrusted tool outputs and reports when a
// later call's arguments are derived from them. It is safe for concurrent use:
// the proxy observes results on one goroutine while evaluating calls on another.
type Tracker struct {
	mu        sync.Mutex
	minLength int
	// sources maps a tainted fragment to the tool whose output introduced it.
	// The first source to introduce a fragment wins.
	sources map[string]string
}

// Hit describes a single tainted-argument match.
type Hit struct {
	// Field is the call argument whose value was derived from untrusted output.
	Field string
	// SourceTool is the tool whose output introduced the tainted fragment.
	SourceTool string
	// Fragment is a short, display-safe excerpt of the matched value.
	Fragment string
}

// fragmentDisplayLimit bounds how many runes of a tainted fragment appear in a
// Hit, so audit reasons stay compact and do not echo an entire tool output.
const fragmentDisplayLimit = 48

// Bounds on what a single Observe call retains, so a large or token-dense tool
// output cannot force unbounded allocation or map growth — a DoS vector, since
// stdio frames can be up to 16 MiB. maxObserveRunes caps the retained text,
// maxObserveTokens caps tokens per observation, and maxTrackedFragments caps the
// session-wide fragment map (which also bounds Check()'s per-call cost).
const (
	maxObserveRunes     = 64 * 1024
	maxObserveTokens    = 4096
	maxTrackedFragments = 1 << 16
)

// NewTracker returns a Tracker that ignores fragments shorter than minLength
// runes (after trimming). A minLength <= 0 falls back to 1, which tracks every
// non-empty fragment.
func NewTracker(minLength int) *Tracker {
	if minLength <= 0 {
		minLength = 1
	}
	return &Tracker{minLength: minLength, sources: map[string]string{}}
}

// Observe records text emitted by sourceTool as untrusted. Both the whole text
// and its whitespace-delimited tokens are remembered, so a later argument that
// reuses an injected token (e.g. a path or URL embedded in a sentence) is still
// caught. Fragments shorter than minLength are ignored to limit false positives.
func (t *Tracker) Observe(sourceTool, text string) {
	if strings.TrimSpace(text) == "" {
		return
	}
	// Bound the retained text before storing/tokenizing it so a large output
	// cannot force unbounded allocation (see maxObserveRunes).
	if r := []rune(text); len(r) > maxObserveRunes {
		text = string(r[:maxObserveRunes])
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.add(sourceTool, text)
	for i, tok := range strings.Fields(text) {
		if i >= maxObserveTokens {
			break
		}
		t.add(sourceTool, tok)
	}
}

func (t *Tracker) add(source, frag string) {
	frag = strings.TrimSpace(frag)
	if len([]rune(frag)) < t.minLength {
		return
	}
	// Cap the session-wide fragment map so a tool that streams many distinct
	// fragments cannot grow it (and Check()'s scan cost) without bound.
	if len(t.sources) >= maxTrackedFragments {
		return
	}
	if _, ok := t.sources[frag]; !ok {
		t.sources[frag] = source
	}
}

// Check reports whether any string-valued argument is derived from a remembered
// untrusted fragment. Argument fields and fragments are scanned in sorted order
// so the reported Hit is deterministic. Returns ok=false when nothing matches.
func (t *Tracker) Check(args map[string]interface{}) (Hit, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(t.sources) == 0 || len(args) == 0 {
		return Hit{}, false
	}

	fields := make([]string, 0, len(args))
	for f := range args {
		fields = append(fields, f)
	}
	sort.Strings(fields)

	frags := make([]string, 0, len(t.sources))
	for frag := range t.sources {
		frags = append(frags, frag)
	}
	sort.Strings(frags)

	for _, field := range fields {
		v, ok := args[field].(string)
		if !ok || len([]rune(v)) < t.minLength {
			continue
		}
		for _, frag := range frags {
			// Three intentional match directions: the argument equals a
			// remembered fragment, contains one (arg embeds an injected token),
			// or is contained by one (arg is a verbatim slice of a larger
			// untrusted output — e.g. a path lifted from a sentence, which the
			// per-token fragments alone would miss for multi-token slices).
			if v == frag || strings.Contains(v, frag) || strings.Contains(frag, v) {
				return Hit{Field: field, SourceTool: t.sources[frag], Fragment: excerpt(frag)}, true
			}
		}
	}
	return Hit{}, false
}

// excerpt truncates a fragment to a display-safe length for audit reasons.
func excerpt(s string) string {
	r := []rune(s)
	if len(r) <= fragmentDisplayLimit {
		return s
	}
	return string(r[:fragmentDisplayLimit]) + "…"
}
