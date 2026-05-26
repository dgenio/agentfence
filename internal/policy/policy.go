package policy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// MaxImportDepth is the maximum number of import levels allowed below the
// root policy file. A root policy (depth 0) can import files (depth 1)
// which can import files (depth 2) which can import files (depth 3); a
// fourth level is rejected. The limit exists to bound resolution cost and
// to discourage policy graphs that are hard to reason about.
const MaxImportDepth = 3

type Decision string

const (
	DecisionAllow Decision = "allow"
	DecisionDeny  Decision = "deny"
	DecisionAsk   Decision = "ask"
)

type ToolCall struct {
	ID        string                 `json:"id"`
	Tool      string                 `json:"tool"`
	Arguments map[string]interface{} `json:"arguments"`
}

type Policy struct {
	Version   string              `yaml:"version"`
	Imports   []string            `yaml:"imports"`
	Defaults  Defaults            `yaml:"defaults"`
	Groups    map[string][]string `yaml:"groups"`
	Tools     map[string]Rule     `yaml:"tools"`
	Redaction RedactionConfig     `yaml:"redaction"`
	Audit     AuditConfig         `yaml:"audit"`
}

type Defaults struct {
	Decision Decision `yaml:"decision"`
}

type Rule struct {
	Decision    Decision    `yaml:"decision"`
	Constraints Constraints `yaml:"constraints"`
}

type Constraints struct {
	Paths       PathConstraints               `yaml:"paths"`
	Args        map[string]ArgValueConstraint `yaml:"args"`
	URLs        URLConstraints                `yaml:"urls"`
	Command     CommandConstraints            `yaml:"command"`
	MemoryWrite MemoryWriteConstraints        `yaml:"memory_write"`
}

type PathConstraints struct {
	Allow []string `yaml:"allow"`
	Deny  []string `yaml:"deny"`
}

// ArgValueConstraint allows/denies specific argument field values using glob patterns.
type ArgValueConstraint struct {
	Allow []string `yaml:"allow"`
	Deny  []string `yaml:"deny"`
}

// URLConstraints applies glob allow/deny rules to the url argument.
// file:// and bare-IP hostnames are always denied regardless of the allow list.
type URLConstraints struct {
	Allow []string `yaml:"allow"`
	Deny  []string `yaml:"deny"`
}

// CommandConstraints restricts shell/terminal tool commands.
// Note: this is a best-effort guardrail, not a sandbox. Shell metacharacters
// (|, ;, &&, $()) can be used to bypass allow_executables and deny_patterns.
type CommandConstraints struct {
	AllowExecutables []string `yaml:"allow_executables"`
	DenyPatterns     []string `yaml:"deny_patterns"`
}

// MemoryWriteConstraints classifies durable memory writes by scope, payload
// sensitivity, and size. A rule that sets any of these fields opts in to
// memory-write evaluation.
//
// Scope ordering (broadest last):    session < project < global
// Sensitivity ordering (highest last): low < medium < high
//
// MaxScope rejects a call whose scope argument is broader than the limit.
// The default scope when the argument is missing is "session".
//
// MaxSensitivity rejects a call whose payload sensitivity exceeds the
// limit. Sensitivity is the maximum of (a) the explicit sensitivity
// argument, if present, and (b) the auto-classified sensitivity from
// running the redactor patterns against the payload (any match → high).
//
// MaxBytes rejects payloads larger than the limit. Zero means no limit.
//
// PayloadFields lists the argument keys that hold the durable payload.
// When empty, ["value", "content"] is used. The first non-empty field
// in this list wins for sensitivity and size checks.
type MemoryWriteConstraints struct {
	MaxScope       string   `yaml:"max_scope"`
	MaxSensitivity string   `yaml:"max_sensitivity"`
	MaxBytes       int      `yaml:"max_bytes"`
	PayloadFields  []string `yaml:"payload_fields"`
}

// IsSet reports whether the rule opts in to memory-write evaluation.
func (m MemoryWriteConstraints) IsSet() bool {
	return m.MaxScope != "" || m.MaxSensitivity != "" || m.MaxBytes > 0 || len(m.PayloadFields) > 0
}

type RedactionConfig struct {
	Enabled  bool               `yaml:"enabled"`
	Patterns []RedactionPattern `yaml:"patterns"`
}

type RedactionPattern struct {
	Name  string `yaml:"name"`
	Regex string `yaml:"regex"`
}

type AuditConfig struct {
	Format                   string `yaml:"format"`
	IncludeRedactedArguments bool   `yaml:"include_redacted_arguments"`
}

type EvaluationResult struct {
	Decision Decision `json:"decision"`
	Reason   string   `json:"reason"`
}

const StarterPolicyYAML = `version: "0.1"

defaults:
  decision: deny

tools:
  filesystem.read:
    decision: allow
    constraints:
      paths:
        allow:
          - "./"
        deny:
          - ".env"
          - "**/secrets/**"

  filesystem.write:
    decision: ask
    constraints:
      paths:
        allow:
          - "./src/**"
          - "./docs/**"
        deny:
          - ".github/workflows/**"
          - ".env"
          - "**/secrets/**"

  github.create_issue:
    decision: ask

  github.delete_repo:
    decision: deny

redaction:
  enabled: true
  patterns:
    - name: openai_api_key
      regex: "sk-[A-Za-z0-9_-]{20,}"
    - name: github_token
      regex: "gh[pousr]_[A-Za-z0-9_]{20,}"
    - name: generic_secret_assignment
      regex: "(?i)(api_key|token|secret|password)\\s*[:=]\\s*[^\\s]+"

audit:
  format: jsonl
  include_redacted_arguments: true
`

// LoadFile loads a policy from a YAML file, resolving any imports declared
// in the imports field. Imports are merged with the importing policy taking
// precedence on key conflicts; redaction patterns from all files are
// unioned. See MaxImportDepth and resolveImports for the limits and
// safety checks applied during resolution.
func LoadFile(path string) (Policy, error) {
	return loadResolved(path, map[string]bool{}, 0)
}

// loadResolved is the recursive worker behind LoadFile. The stack argument
// holds the canonical absolute paths of every file currently being resolved
// — recursing into a file already on the stack is a circular import.
func loadResolved(path string, stack map[string]bool, depth int) (Policy, error) {
	if depth > MaxImportDepth {
		return Policy{}, fmt.Errorf("import depth exceeds limit of %d at %q", MaxImportDepth, path)
	}

	canon, err := canonicalizePath(path)
	if err != nil {
		return Policy{}, fmt.Errorf("resolve %q: %w", path, err)
	}
	if stack[canon] {
		return Policy{}, fmt.Errorf("circular import detected at %q", path)
	}

	b, err := os.ReadFile(path)
	if err != nil {
		return Policy{}, err
	}
	p, err := ParsePolicy(b)
	if err != nil {
		return Policy{}, fmt.Errorf("parse %q: %w", path, err)
	}

	if len(p.Imports) == 0 {
		return p, nil
	}

	// Build a new stack containing this file so cycles are detected.
	newStack := make(map[string]bool, len(stack)+1)
	for k, v := range stack {
		newStack[k] = v
	}
	newStack[canon] = true

	importerDir := filepath.Dir(canon)
	resolved := Policy{}
	for _, imp := range p.Imports {
		if imp == "" {
			return Policy{}, fmt.Errorf("import in %q: empty path", path)
		}
		if filepath.IsAbs(imp) || strings.HasPrefix(filepath.ToSlash(imp), "/") {
			return Policy{}, fmt.Errorf("import %q in %q: absolute paths are not allowed", imp, path)
		}
		absImp, err := filepath.Abs(filepath.Join(importerDir, imp))
		if err != nil {
			return Policy{}, fmt.Errorf("import %q in %q: %w", imp, path, err)
		}
		canonImp, err := canonicalizePath(absImp)
		if err != nil {
			return Policy{}, fmt.Errorf("resolve import %q in %q: %w", imp, path, err)
		}
		if !pathWithin(importerDir, canonImp) {
			return Policy{}, fmt.Errorf("import %q in %q: escapes the importing file's directory", imp, path)
		}
		child, err := loadResolved(canonImp, newStack, depth+1)
		if err != nil {
			return Policy{}, err
		}
		resolved = mergePolicy(resolved, child)
	}

	// The importing policy overrides anything inherited from imports.
	resolved = mergePolicy(resolved, p)
	// Imports have been resolved; clear the field so downstream code sees
	// only the merged result.
	resolved.Imports = nil
	// Defaults that ParsePolicy applied to individual files may have been
	// overridden during merge; re-apply to keep invariants.
	applyDefaults(&resolved)
	return resolved, nil
}

// canonicalizePath returns an absolute, symlink-resolved path used for cycle
// detection. It falls back to filepath.Abs when EvalSymlinks fails (for
// example because the file doesn't exist yet — caller will fail later when
// it tries to read it).
func canonicalizePath(p string) (string, error) {
	abs, err := filepath.Abs(p)
	if err != nil {
		return "", err
	}
	if resolved, err := filepath.EvalSymlinks(abs); err == nil {
		return resolved, nil
	}
	return abs, nil
}

// pathWithin reports whether target is the same as or a descendant of base.
// Both arguments must be absolute paths.
func pathWithin(base, target string) bool {
	rel, err := filepath.Rel(base, target)
	if err != nil {
		return false
	}
	if rel == ".." {
		return false
	}
	if strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return false
	}
	return true
}

// mergePolicy returns base with overlay layered on top. Importing-policy-wins
// semantics:
//   - Version: overlay wins when non-empty.
//   - Defaults.Decision: overlay wins when non-empty.
//   - Tools and Groups: maps are unioned; on key conflict overlay wins.
//   - Redaction.Patterns: unioned (overlay appended after base) so both
//     bases' and overlay's regexes run during redaction.
//   - Redaction.Enabled and Audit.IncludeRedactedArguments: OR semantics —
//     once any layer enables them they stay enabled. This is the safer
//     direction for a security tool and is documented in the policy guide.
//   - Audit.Format: overlay wins when non-empty.
//
// When sibling imports conflict (two imports of the same tool key, for
// example), the later import wins because that file is applied later.
func mergePolicy(base, overlay Policy) Policy {
	out := base

	if overlay.Version != "" {
		out.Version = overlay.Version
	}
	if overlay.Defaults.Decision != "" {
		out.Defaults.Decision = overlay.Defaults.Decision
	}

	if out.Tools == nil {
		out.Tools = map[string]Rule{}
	}
	for k, v := range overlay.Tools {
		out.Tools[k] = v
	}

	if out.Groups == nil {
		out.Groups = map[string][]string{}
	}
	for k, v := range overlay.Groups {
		out.Groups[k] = v
	}

	if overlay.Redaction.Enabled {
		out.Redaction.Enabled = true
	}
	out.Redaction.Patterns = append(out.Redaction.Patterns, overlay.Redaction.Patterns...)

	if overlay.Audit.Format != "" {
		out.Audit.Format = overlay.Audit.Format
	}
	if overlay.Audit.IncludeRedactedArguments {
		out.Audit.IncludeRedactedArguments = true
	}

	return out
}

// applyDefaults restores invariants on a Policy after a merge or fresh parse:
// non-empty Defaults.Decision, non-nil Tools/Groups maps, and non-empty
// Audit.Format.
func applyDefaults(p *Policy) {
	if p.Defaults.Decision == "" {
		p.Defaults.Decision = DecisionDeny
	}
	if p.Tools == nil {
		p.Tools = map[string]Rule{}
	}
	if p.Groups == nil {
		p.Groups = map[string][]string{}
	}
	if p.Audit.Format == "" {
		p.Audit.Format = "jsonl"
	}
}

func ParsePolicy(b []byte) (Policy, error) {
	var p Policy
	if err := yaml.Unmarshal(b, &p); err != nil {
		return Policy{}, err
	}

	applyDefaults(&p)

	if err := validateDecision(p.Defaults.Decision); err != nil {
		return Policy{}, fmt.Errorf("defaults.decision: %w", err)
	}
	for name, rule := range p.Tools {
		if err := validateDecision(rule.Decision); err != nil {
			return Policy{}, fmt.Errorf("tools.%s.decision: %w", name, err)
		}
		if err := validateMemoryWrite(rule.Constraints.MemoryWrite); err != nil {
			return Policy{}, fmt.Errorf("tools.%s.constraints.memory_write: %w", name, err)
		}
	}
	if err := validateAuditFormat(p.Audit.Format); err != nil {
		return Policy{}, fmt.Errorf("audit.format: %w", err)
	}
	return p, nil
}

func ParseToolCall(line []byte) (ToolCall, error) {
	var call ToolCall
	if err := json.Unmarshal(line, &call); err != nil {
		return ToolCall{}, err
	}
	if call.ID == "" || call.Tool == "" {
		return ToolCall{}, fmt.Errorf("tool call requires id and tool")
	}
	if call.Arguments == nil {
		call.Arguments = map[string]interface{}{}
	}
	return call, nil
}

func validateDecision(d Decision) error {
	switch d {
	case DecisionAllow, DecisionDeny, DecisionAsk:
		return nil
	default:
		return fmt.Errorf("must be one of allow, deny, ask")
	}
}

func validateAuditFormat(f string) error {
	switch f {
	case "jsonl":
		return nil
	default:
		return fmt.Errorf("unsupported format %q; supported: jsonl", f)
	}
}

// MemoryScopes and MemorySensitivities are the valid ordered values for the
// MemoryWrite constraint fields. Order is significant: position in the
// slice equals rank (lower index = narrower scope / lower sensitivity).
var (
	MemoryScopes         = []string{"session", "project", "global"}
	MemorySensitivities  = []string{"low", "medium", "high"}
	DefaultPayloadFields = []string{"value", "content"}
)

// MemoryScopeRank returns the rank (0-indexed) of s in MemoryScopes.
// Returns -1 when s is not a recognised scope.
func MemoryScopeRank(s string) int {
	for i, v := range MemoryScopes {
		if v == s {
			return i
		}
	}
	return -1
}

// MemorySensitivityRank returns the rank (0-indexed) of s in
// MemorySensitivities. Returns -1 when s is not a recognised sensitivity.
func MemorySensitivityRank(s string) int {
	for i, v := range MemorySensitivities {
		if v == s {
			return i
		}
	}
	return -1
}

func validateMemoryWrite(m MemoryWriteConstraints) error {
	if m.MaxScope != "" && MemoryScopeRank(m.MaxScope) < 0 {
		return fmt.Errorf("max_scope: must be one of %s (got %q)", strings.Join(MemoryScopes, ", "), m.MaxScope)
	}
	if m.MaxSensitivity != "" && MemorySensitivityRank(m.MaxSensitivity) < 0 {
		return fmt.Errorf("max_sensitivity: must be one of %s (got %q)", strings.Join(MemorySensitivities, ", "), m.MaxSensitivity)
	}
	if m.MaxBytes < 0 {
		return fmt.Errorf("max_bytes: must be >= 0 (got %d)", m.MaxBytes)
	}
	return nil
}

// ValidationError describes a single policy validation problem.
type ValidationError struct {
	Field   string
	Value   string
	Message string
}

func (e ValidationError) Error() string {
	if e.Field == "" {
		return e.Message
	}
	if e.Value == "" {
		return fmt.Sprintf("%s: %s", e.Field, e.Message)
	}
	return fmt.Sprintf("%s: %s (got %q)", e.Field, e.Message, e.Value)
}

// ValidateStrict parses b with unknown-field detection enabled and runs semantic
// validation. All errors are collected and returned; the caller should check
// len(errs) > 0. Does not modify the behaviour of ParsePolicy or LoadFile.
func ValidateStrict(b []byte) []ValidationError {
	var errs []ValidationError

	// Structural pass: use KnownFields(true) to catch typos in field names.
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	var p Policy
	if err := dec.Decode(&p); err != nil {
		errs = append(errs, ValidationError{Field: "", Message: err.Error()})
		return errs // semantic checks are not meaningful if the schema is wrong
	}

	// Semantic pass: collect all issues rather than failing on the first.
	if p.Version == "" {
		errs = append(errs, ValidationError{Field: "version", Message: "version field is required"})
	}

	if p.Defaults.Decision != "" {
		if err := validateDecision(p.Defaults.Decision); err != nil {
			errs = append(errs, ValidationError{
				Field:   "defaults.decision",
				Value:   string(p.Defaults.Decision),
				Message: "must be one of allow, deny, ask",
			})
		}
	}

	for name, rule := range p.Tools {
		if err := validateDecision(rule.Decision); err != nil {
			errs = append(errs, ValidationError{
				Field:   fmt.Sprintf("tools.%s.decision", name),
				Value:   string(rule.Decision),
				Message: "must be one of allow, deny, ask",
			})
		}
		mw := rule.Constraints.MemoryWrite
		if mw.MaxScope != "" && MemoryScopeRank(mw.MaxScope) < 0 {
			errs = append(errs, ValidationError{
				Field:   fmt.Sprintf("tools.%s.constraints.memory_write.max_scope", name),
				Value:   mw.MaxScope,
				Message: fmt.Sprintf("must be one of %s", strings.Join(MemoryScopes, ", ")),
			})
		}
		if mw.MaxSensitivity != "" && MemorySensitivityRank(mw.MaxSensitivity) < 0 {
			errs = append(errs, ValidationError{
				Field:   fmt.Sprintf("tools.%s.constraints.memory_write.max_sensitivity", name),
				Value:   mw.MaxSensitivity,
				Message: fmt.Sprintf("must be one of %s", strings.Join(MemorySensitivities, ", ")),
			})
		}
		if mw.MaxBytes < 0 {
			errs = append(errs, ValidationError{
				Field:   fmt.Sprintf("tools.%s.constraints.memory_write.max_bytes", name),
				Value:   fmt.Sprintf("%d", mw.MaxBytes),
				Message: "must be >= 0",
			})
		}
	}

	for _, pat := range p.Redaction.Patterns {
		if _, err := regexp.Compile(pat.Regex); err != nil {
			errs = append(errs, ValidationError{
				Field:   fmt.Sprintf("redaction.patterns.%s.regex", pat.Name),
				Value:   pat.Regex,
				Message: fmt.Sprintf("invalid regex: %s", err),
			})
		}
	}

	if p.Audit.Format != "" {
		if err := validateAuditFormat(p.Audit.Format); err != nil {
			errs = append(errs, ValidationError{
				Field:   "audit.format",
				Value:   p.Audit.Format,
				Message: "unsupported format; supported: jsonl",
			})
		}
	}

	return errs
}

// PolicyTest is a single test case in a policy test fixture.
type PolicyTest struct {
	ID        string                 `yaml:"id"`
	Tool      string                 `yaml:"tool"`
	Arguments map[string]interface{} `yaml:"arguments"`
	Expect    Decision               `yaml:"expect"`
}

// PolicyTestFixture is the top-level structure for a policy test YAML file.
type PolicyTestFixture struct {
	Tests []PolicyTest `yaml:"tests"`
}

// ParsePolicyTestFixture parses a YAML policy test fixture file.
// It uses KnownFields(true) to reject unknown keys and catch typos.
func ParsePolicyTestFixture(b []byte) (PolicyTestFixture, error) {
	var f PolicyTestFixture
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(&f); err != nil {
		return PolicyTestFixture{}, err
	}
	if len(f.Tests) == 0 {
		return PolicyTestFixture{}, fmt.Errorf("policy test fixture contains no tests")
	}
	for i, tc := range f.Tests {
		if tc.ID == "" {
			return PolicyTestFixture{}, fmt.Errorf("test[%d]: id is required", i)
		}
		if tc.Tool == "" {
			return PolicyTestFixture{}, fmt.Errorf("test %q: tool is required", tc.ID)
		}
		if err := validateDecision(tc.Expect); err != nil {
			return PolicyTestFixture{}, fmt.Errorf("test %q: expect: %w", tc.ID, err)
		}
	}
	return f, nil
}
