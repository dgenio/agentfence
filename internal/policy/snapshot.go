package policy

import (
	"encoding/json"
	"fmt"

	"gopkg.in/yaml.v3"
)

// SnapshotToolCall returns an exact deep copy of a tool call suitable for
// digesting and evaluating as one immutable decision input.
//
// Floating-point values are rejected because the original JSON number token may
// already have been rounded or normalized before this function sees it.
func SnapshotToolCall(call ToolCall) (ToolCall, error) {
	arguments, err := snapshotExactValue(call.Arguments)
	if err != nil {
		return ToolCall{}, fmt.Errorf("tool call snapshot: %w", err)
	}
	argumentMap, ok := arguments.(map[string]interface{})
	if !ok && arguments != nil {
		return ToolCall{}, fmt.Errorf("tool call snapshot: arguments have type %T, want object", arguments)
	}
	if argumentMap == nil {
		argumentMap = map[string]interface{}{}
	}
	return ToolCall{ID: call.ID, Tool: call.Tool, Arguments: argumentMap}, nil
}

// SnapshotResolvedPolicy returns a validated deep copy of a resolved effective
// policy. Imports must already have been resolved so the snapshot itself is the
// complete policy input used for both digesting and evaluation.
func SnapshotResolvedPolicy(p Policy) (Policy, error) {
	if len(p.Imports) != 0 {
		return Policy{}, fmt.Errorf("policy snapshot: unresolved imports are not allowed")
	}
	raw, err := yaml.Marshal(p)
	if err != nil {
		return Policy{}, fmt.Errorf("policy snapshot: marshal: %w", err)
	}
	snapshot, err := ParsePolicy(raw)
	if err != nil {
		return Policy{}, fmt.Errorf("policy snapshot: invalid policy: %w", err)
	}
	if len(snapshot.Imports) != 0 {
		return Policy{}, fmt.Errorf("policy snapshot: unresolved imports are not allowed")
	}
	return snapshot, nil
}

func snapshotExactValue(value interface{}) (interface{}, error) {
	switch v := value.(type) {
	case nil, bool, string, json.Number,
		int, int8, int16, int32, int64,
		uint, uint8, uint16, uint32, uint64:
		return v, nil
	case float32, float64:
		return nil, fmt.Errorf("floating-point argument type %T is not exact; parse JSON with UseNumber", value)
	case []interface{}:
		out := make([]interface{}, len(v))
		for i, item := range v {
			copyItem, err := snapshotExactValue(item)
			if err != nil {
				return nil, fmt.Errorf("arguments[%d]: %w", i, err)
			}
			out[i] = copyItem
		}
		return out, nil
	case map[string]interface{}:
		out := make(map[string]interface{}, len(v))
		for key, item := range v {
			copyItem, err := snapshotExactValue(item)
			if err != nil {
				return nil, fmt.Errorf("arguments[%q]: %w", key, err)
			}
			out[key] = copyItem
		}
		return out, nil
	default:
		return nil, fmt.Errorf("unsupported argument type %T", value)
	}
}
