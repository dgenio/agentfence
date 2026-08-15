package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/dgenio/agentfence/internal/exactjson"
	"gopkg.in/yaml.v3"
)

const (
	// ResolvedPolicyDigestAlgorithm identifies the v1 effective-policy
	// projection and digest contract. It is deliberately brand-neutral so a
	// product rename does not invalidate content identity.
	ResolvedPolicyDigestAlgorithm = "resolved-policy-json-v1"
	// ToolActionDigestAlgorithm identifies the v1 exact tool-action projection
	// and digest contract. Request/correlation IDs are intentionally excluded.
	ToolActionDigestAlgorithm = "tool-action-json-v1"
)

// EffectivePolicyDigest returns a deterministic identity for the complete
// resolved policy that the engine evaluates.
//
// Imports must already have been resolved (normally via LoadFile). The policy
// is revalidated and defaults are reapplied before projection. The v1 contract
// conservatively includes the complete resolved policy, including redaction,
// audit, and taint configuration, while excluding the now-resolved Imports
// field itself.
func EffectivePolicyDigest(p Policy) (string, error) {
	if len(p.Imports) != 0 {
		return "", fmt.Errorf("effective policy digest: unresolved imports are not allowed")
	}

	// Re-parse the in-memory model through the repository's policy decoder so
	// callers cannot obtain a durable digest for a malformed or non-normalized
	// Policy assembled by hand.
	raw, err := yaml.Marshal(p)
	if err != nil {
		return "", fmt.Errorf("effective policy digest: marshal for validation: %w", err)
	}
	normalized, err := ParsePolicy(raw)
	if err != nil {
		return "", fmt.Errorf("effective policy digest: invalid policy: %w", err)
	}
	if len(normalized.Imports) != 0 {
		return "", fmt.Errorf("effective policy digest: unresolved imports are not allowed")
	}

	projection, err := policyProjection(normalized)
	if err != nil {
		return "", err
	}
	return digestProjection(ResolvedPolicyDigestAlgorithm, projection)
}

// ToolActionDigest returns a deterministic identity for the policy-relevant
// tool action: tool name plus exact arguments. ToolCall.ID is correlation
// evidence and is deliberately excluded.
//
// Calls parsed through the protected JSON path carry json.Number values, which
// preserve lexical distinctions such as 1, 1.0, and 1.00. float32/float64 are
// rejected because their original request representation may already have been
// rounded or normalized before this function sees it.
func ToolActionDigest(call ToolCall) (string, error) {
	if err := rejectLossyNumbers(call.Arguments); err != nil {
		return "", fmt.Errorf("tool action digest: %w", err)
	}

	arguments := call.Arguments
	if arguments == nil {
		arguments = map[string]interface{}{}
	}
	projection := map[string]interface{}{
		"tool":      call.Tool,
		"arguments": arguments,
	}
	return digestProjection(ToolActionDigestAlgorithm, projection)
}

func policyProjection(p Policy) (interface{}, error) {
	// Policy structs intentionally use yaml tags as the user-facing field names.
	// Convert the validated resolved model through those tags into a generic
	// value, then canonicalize the resulting JSON. We do not hash YAML bytes.
	raw, err := yaml.Marshal(p)
	if err != nil {
		return nil, fmt.Errorf("effective policy digest: project policy: %w", err)
	}
	var projection interface{}
	if err := yaml.Unmarshal(raw, &projection); err != nil {
		return nil, fmt.Errorf("effective policy digest: decode projection: %w", err)
	}
	root, ok := projection.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("effective policy digest: projection root has type %T, want object", projection)
	}
	delete(root, "imports")
	return root, nil
}

func digestProjection(algorithm string, projection interface{}) (string, error) {
	raw, err := json.Marshal(projection)
	if err != nil {
		return "", fmt.Errorf("%s: marshal projection: %w", algorithm, err)
	}
	canonical, err := exactjson.Canonicalize(raw)
	if err != nil {
		return "", fmt.Errorf("%s: canonicalize projection: %w", algorithm, err)
	}
	sum := sha256.Sum256(canonical)
	return algorithm + ":sha256:" + hex.EncodeToString(sum[:]), nil
}

func rejectLossyNumbers(value interface{}) error {
	switch v := value.(type) {
	case nil, bool, string, json.Number:
		return nil
	case float32, float64:
		return fmt.Errorf("floating-point argument type %T is not exact; parse JSON with UseNumber", value)
	case int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64:
		return nil
	case []interface{}:
		for i, item := range v {
			if err := rejectLossyNumbers(item); err != nil {
				return fmt.Errorf("arguments[%d]: %w", i, err)
			}
		}
		return nil
	case map[string]interface{}:
		for key, item := range v {
			if err := rejectLossyNumbers(item); err != nil {
				return fmt.Errorf("arguments[%q]: %w", key, err)
			}
		}
		return nil
	default:
		return fmt.Errorf("unsupported argument type %T", value)
	}
}
