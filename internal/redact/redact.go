package redact

import (
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
