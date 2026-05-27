package redact

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"

	"github.com/dgenio/agentfence/internal/policy"
)

type compiledPattern struct {
	name  string
	regex *regexp.Regexp
}

type Redactor struct {
	enabled  bool
	patterns []compiledPattern
}

func New(cfg policy.RedactionConfig) (*Redactor, error) {
	r := &Redactor{enabled: cfg.Enabled}
	for _, p := range cfg.Patterns {
		re, err := regexp.Compile(p.Regex)
		if err != nil {
			return nil, fmt.Errorf("compile redaction pattern %q: %w", p.Name, err)
		}
		r.patterns = append(r.patterns, compiledPattern{name: p.Name, regex: re})
	}
	return r, nil
}

func (r *Redactor) RedactArguments(args map[string]interface{}) map[string]interface{} {
	if args == nil {
		return nil
	}
	cloned := make(map[string]interface{}, len(args))
	for k, v := range args {
		cloned[k] = r.redactValue(v)
	}
	return cloned
}

// MatchesAny reports whether s matches any configured redaction pattern.
// Returns false when redaction is disabled — callers that want to inspect
// patterns regardless should not gate on enabled state.
func (r *Redactor) MatchesAny(s string) bool {
	if !r.enabled {
		return false
	}
	return r.MatchesConfiguredPattern(s)
}

// MatchedPatternNames returns the names of every configured redaction
// pattern that matches s. The order matches the order patterns were
// configured. Returns nil when redaction is disabled or no pattern matches.
func (r *Redactor) MatchedPatternNames(s string) []string {
	if !r.enabled {
		return nil
	}
	return r.MatchedConfiguredPatternNames(s)
}

// MatchesConfiguredPattern reports whether s matches any configured redaction
// pattern, regardless of whether audit redaction is enabled.
func (r *Redactor) MatchesConfiguredPattern(s string) bool {
	return len(r.MatchedConfiguredPatternNames(s)) > 0
}

// MatchedConfiguredPatternNames returns matching pattern names regardless of
// whether audit redaction is enabled. The order matches configuration order.
func (r *Redactor) MatchedConfiguredPatternNames(s string) []string {
	var names []string
	for _, p := range r.patterns {
		if p.regex.MatchString(s) {
			names = append(names, p.name)
		}
	}
	return names
}

// FingerprintPayload returns a short hex prefix of the SHA-256 of s. It is
// safe to log: collision-resistant for casual comparison but reveals no
// information about the original payload. Used in audit summaries so two
// memory writes of the same value can be correlated without exposing the
// value.
func FingerprintPayload(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])[:12]
}

func (r *Redactor) redactValue(v interface{}) interface{} {
	if !r.enabled {
		return v
	}
	if v == nil {
		return nil
	}
	switch x := v.(type) {
	case string:
		out := x
		for _, p := range r.patterns {
			out = p.regex.ReplaceAllString(out, "[REDACTED:"+p.name+"]")
		}
		return out
	case map[string]interface{}:
		m := make(map[string]interface{}, len(x))
		for k, vv := range x {
			m[k] = r.redactValue(vv)
		}
		return m
	case []interface{}:
		arr := make([]interface{}, len(x))
		for i := range x {
			arr[i] = r.redactValue(x[i])
		}
		return arr
	default:
		return v
	}
}
