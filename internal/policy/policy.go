package policy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"regexp"

	"gopkg.in/yaml.v3"
)

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
	Version   string          `yaml:"version"`
	Defaults  Defaults        `yaml:"defaults"`
	Tools     map[string]Rule `yaml:"tools"`
	Redaction RedactionConfig `yaml:"redaction"`
	Audit     AuditConfig     `yaml:"audit"`
}

type Defaults struct {
	Decision Decision `yaml:"decision"`
}

type Rule struct {
	Decision    Decision    `yaml:"decision"`
	Constraints Constraints `yaml:"constraints"`
}

type Constraints struct {
	Paths PathConstraints `yaml:"paths"`
}

type PathConstraints struct {
	Allow []string `yaml:"allow"`
	Deny  []string `yaml:"deny"`
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

func LoadFile(path string) (Policy, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return Policy{}, err
	}
	return ParsePolicy(b)
}

func ParsePolicy(b []byte) (Policy, error) {
	var p Policy
	if err := yaml.Unmarshal(b, &p); err != nil {
		return Policy{}, err
	}

	if p.Defaults.Decision == "" {
		p.Defaults.Decision = DecisionDeny
	}
	if p.Tools == nil {
		p.Tools = map[string]Rule{}
	}
	if p.Audit.Format == "" {
		p.Audit.Format = "jsonl"
	}

	if err := validateDecision(p.Defaults.Decision); err != nil {
		return Policy{}, fmt.Errorf("defaults.decision: %w", err)
	}
	for name, rule := range p.Tools {
		if err := validateDecision(rule.Decision); err != nil {
			return Policy{}, fmt.Errorf("tools.%s.decision: %w", name, err)
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
