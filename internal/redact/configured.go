package redact

// RedactArgumentsConfigured returns a deep redacted copy of args using every
// configured pattern regardless of RedactionConfig.Enabled.
//
// Approval displays use this stricter path: disabling audit-argument redaction
// must never make an interactive approval prompt fall back to raw secret-bearing
// values when patterns are available.
func (r *Redactor) RedactArgumentsConfigured(args map[string]interface{}) map[string]interface{} {
	if args == nil {
		return nil
	}
	cloned := make(map[string]interface{}, len(args))
	for key, value := range args {
		cloned[key] = r.redactConfiguredValue(value)
	}
	return cloned
}

func (r *Redactor) redactConfiguredValue(value interface{}) interface{} {
	if value == nil {
		return nil
	}
	switch v := value.(type) {
	case string:
		out := v
		for _, pattern := range r.patterns {
			marker := "[REDACTED:" + pattern.name + "]"
			// Use a callback so '$1'-style text in an operator-chosen pattern
			// name is literal marker text, never a regexp capture expansion that
			// could reinsert matched secret content into the approval display.
			out = pattern.regex.ReplaceAllStringFunc(out, func(string) string { return marker })
		}
		return out
	case map[string]interface{}:
		out := make(map[string]interface{}, len(v))
		for key, item := range v {
			out[key] = r.redactConfiguredValue(item)
		}
		return out
	case []interface{}:
		out := make([]interface{}, len(v))
		for i, item := range v {
			out[i] = r.redactConfiguredValue(item)
		}
		return out
	default:
		return v
	}
}
