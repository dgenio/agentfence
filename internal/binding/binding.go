// Package binding computes deterministic, brand-neutral identities for the
// exact tool action and resolved policy that participate in authorization.
//
// It is intentionally pure. These identities are not yet emitted in the public
// audit schema or approval interface; later #222 slices will bind those
// surfaces to the same values after this contract is reviewed and tested.
package binding

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"reflect"

	"github.com/dgenio/agentfence/internal/exactjson"
	"github.com/dgenio/agentfence/internal/policy"
)

const (
	ActionAlgorithm = "tool-action-json-v1"
	PolicyAlgorithm = "resolved-policy-json-v1"
)

// ActionDigest identifies the semantic tool action the authorization decision
// refers to. The call ID is intentionally excluded: it is correlation evidence,
// not authority. Tool and the complete argument object are included.
//
// Numeric arguments must be json.Number rather than float/int types so callers
// cannot accidentally fingerprint a value after lossy or implementation-
// dependent numeric conversion. Runtime JSON tool-call paths satisfy this once
// #232 is in place.
func ActionDigest(call policy.ToolCall) (string, error) {
	if call.Tool == "" {
		return "", fmt.Errorf("action binding: tool must not be empty")
	}
	if call.Arguments == nil {
		call.Arguments = map[string]interface{}{}
	}
	if err := validateExactJSONValue(call.Arguments, "arguments"); err != nil {
		return "", err
	}

	projection := struct {
		Tool      string                 `json:"tool"`
		Arguments map[string]interface{} `json:"arguments"`
	}{Tool: call.Tool, Arguments: call.Arguments}

	raw, err := json.Marshal(projection)
	if err != nil {
		return "", fmt.Errorf("action binding: marshal: %w", err)
	}
	canonical, err := exactjson.Canonicalize(raw)
	if err != nil {
		return "", fmt.Errorf("action binding: canonicalize: %w", err)
	}
	return digest(ActionAlgorithm, canonical), nil
}

// EffectivePolicyDigest identifies the fully resolved Policy that the engine
// evaluates. The caller must pass a resolved policy (normally from LoadFile);
// unresolved Imports are rejected rather than being silently ignored.
//
// Version 1 deliberately fingerprints the complete resolved configuration,
// including redaction/audit/taint configuration. This is conservative: a
// configuration-only change may produce a new identity even when a narrower
// authorization outcome would not change, but the receipt can always identify
// the exact engine/evidence configuration that ran.
func EffectivePolicyDigest(p policy.Policy) (string, error) {
	if len(p.Imports) != 0 {
		return "", fmt.Errorf("policy binding: policy contains unresolved imports")
	}
	projection := projectPolicy(p)
	raw, err := json.Marshal(projection)
	if err != nil {
		return "", fmt.Errorf("policy binding: marshal: %w", err)
	}
	canonical, err := exactjson.Canonicalize(raw)
	if err != nil {
		return "", fmt.Errorf("policy binding: canonicalize: %w", err)
	}
	return digest(PolicyAlgorithm, canonical), nil
}

func digest(algorithm string, canonical []byte) string {
	sum := sha256.Sum256(canonical)
	return algorithm + ":sha256:" + hex.EncodeToString(sum[:])
}

func validateExactJSONValue(value interface{}, path string) error {
	switch v := value.(type) {
	case nil, bool, string, json.Number:
		return nil
	case map[string]interface{}:
		for key, child := range v {
			if err := validateExactJSONValue(child, path+"."+key); err != nil {
				return err
			}
		}
		return nil
	case []interface{}:
		for i, child := range v {
			if err := validateExactJSONValue(child, fmt.Sprintf("%s[%d]", path, i)); err != nil {
				return err
			}
		}
		return nil
	default:
		t := reflect.TypeOf(value)
		return fmt.Errorf("action binding: %s uses non-exact JSON value type %v; numeric values must be json.Number", path, t)
	}
}

type policyProjection struct {
	Version   string                         `json:"version"`
	Defaults  defaultsProjection             `json:"defaults"`
	Groups    map[string][]string             `json:"groups"`
	Tools     map[string]ruleProjection       `json:"tools"`
	Redaction redactionProjection             `json:"redaction"`
	Audit     auditProjection                 `json:"audit"`
	Taint     taintProjection                 `json:"taint"`
}

type defaultsProjection struct {
	Decision policy.Decision `json:"decision"`
}

type ruleProjection struct {
	Decision    policy.Decision       `json:"decision"`
	Constraints constraintsProjection `json:"constraints"`
}

type constraintsProjection struct {
	Paths       pathProjection                     `json:"paths"`
	Args        map[string]argConstraintProjection `json:"args"`
	URLs        urlProjection                      `json:"urls"`
	Command     commandProjection                  `json:"command"`
	MemoryWrite memoryWriteProjection              `json:"memory_write"`
}

type pathProjection struct {
	Allow []string `json:"allow"`
	Deny  []string `json:"deny"`
}

type argConstraintProjection struct {
	Allow []string `json:"allow"`
	Deny  []string `json:"deny"`
}

type urlProjection struct {
	Allow []string `json:"allow"`
	Deny  []string `json:"deny"`
}

type commandProjection struct {
	AllowExecutables []string `json:"allow_executables"`
	DenyPatterns     []string `json:"deny_patterns"`
}

type memoryWriteProjection struct {
	MaxScope       string   `json:"max_scope"`
	MaxSensitivity string   `json:"max_sensitivity"`
	MaxBytes       int      `json:"max_bytes"`
	PayloadFields  []string `json:"payload_fields"`
}

type redactionProjection struct {
	Enabled  bool                       `json:"enabled"`
	Patterns []redactionPatternProjection `json:"patterns"`
}

type redactionPatternProjection struct {
	Name  string `json:"name"`
	Regex string `json:"regex"`
}

type auditProjection struct {
	Format                   string `json:"format"`
	IncludeRedactedArguments bool   `json:"include_redacted_arguments"`
}

type taintProjection struct {
	Enabled           bool   `json:"enabled"`
	OnTaintedArgument string `json:"on_tainted_argument"`
	MinLength         int    `json:"min_length"`
}

func projectPolicy(p policy.Policy) policyProjection {
	groups := make(map[string][]string, len(p.Groups))
	for name, members := range p.Groups {
		groups[name] = stringsSlice(members)
	}

	tools := make(map[string]ruleProjection, len(p.Tools))
	for name, rule := range p.Tools {
		args := make(map[string]argConstraintProjection, len(rule.Constraints.Args))
		for field, constraint := range rule.Constraints.Args {
			args[field] = argConstraintProjection{Allow: stringsSlice(constraint.Allow), Deny: stringsSlice(constraint.Deny)}
		}
		tools[name] = ruleProjection{
			Decision: rule.Decision,
			Constraints: constraintsProjection{
				Paths: pathProjection{Allow: stringsSlice(rule.Constraints.Paths.Allow), Deny: stringsSlice(rule.Constraints.Paths.Deny)},
				Args: args,
				URLs: urlProjection{Allow: stringsSlice(rule.Constraints.URLs.Allow), Deny: stringsSlice(rule.Constraints.URLs.Deny)},
				Command: commandProjection{AllowExecutables: stringsSlice(rule.Constraints.Command.AllowExecutables), DenyPatterns: stringsSlice(rule.Constraints.Command.DenyPatterns)},
				MemoryWrite: memoryWriteProjection{
					MaxScope: rule.Constraints.MemoryWrite.MaxScope,
					MaxSensitivity: rule.Constraints.MemoryWrite.MaxSensitivity,
					MaxBytes: rule.Constraints.MemoryWrite.MaxBytes,
					PayloadFields: stringsSlice(rule.Constraints.MemoryWrite.PayloadFields),
				},
			},
		}
	}

	patterns := make([]redactionPatternProjection, len(p.Redaction.Patterns))
	for i, pattern := range p.Redaction.Patterns {
		patterns[i] = redactionPatternProjection{Name: pattern.Name, Regex: pattern.Regex}
	}

	return policyProjection{
		Version: p.Version,
		Defaults: defaultsProjection{Decision: p.Defaults.Decision},
		Groups: groups,
		Tools: tools,
		Redaction: redactionProjection{Enabled: p.Redaction.Enabled, Patterns: patterns},
		Audit: auditProjection{Format: p.Audit.Format, IncludeRedactedArguments: p.Audit.IncludeRedactedArguments},
		Taint: taintProjection{Enabled: p.Taint.Enabled, OnTaintedArgument: p.Taint.OnTaintedArgument, MinLength: p.Taint.MinLength},
	}
}

func stringsSlice(in []string) []string {
	if len(in) == 0 {
		return []string{}
	}
	out := make([]string, len(in))
	copy(out, in)
	return out
}
