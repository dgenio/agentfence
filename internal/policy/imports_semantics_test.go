package policy

import "testing"

// These tests pin the import merge precedence rules documented in
// docs/policy-language.md ("Policy imports"): importer-wins for scalar fields
// and OR semantics for the security-relevant boolean flags. They complement
// the existing import tests (tools/groups override, redaction-pattern union,
// sibling order, taint OR) by covering the enable flags and scalar precedence.

// The redaction.enabled and audit.include_redacted_arguments flags follow OR
// semantics: once any layer turns them on they stay on, regardless of which
// layer set them. This is the safer direction for a security tool — an import
// cannot quietly disable a base file's redaction.
func TestPolicyImportsEnableFlagsOrSemantics(t *testing.T) {
	t.Run("base enables, importer silent", func(t *testing.T) {
		dir := t.TempDir()
		writeFile(t, dir, "base.yaml", `version: "0.1"
defaults:
  decision: deny
redaction:
  enabled: true
audit:
  include_redacted_arguments: true
`)
		root := writeFile(t, dir, "root.yaml", `version: "0.1"
imports:
  - base.yaml
`)
		p, err := LoadFile(root)
		if err != nil {
			t.Fatalf("LoadFile error: %v", err)
		}
		if !p.Redaction.Enabled {
			t.Error("redaction.enabled should stay true (OR); importer did not disable it")
		}
		if !p.Audit.IncludeRedactedArguments {
			t.Error("audit.include_redacted_arguments should stay true (OR)")
		}
	})

	t.Run("base silent, importer enables", func(t *testing.T) {
		dir := t.TempDir()
		writeFile(t, dir, "base.yaml", `version: "0.1"
defaults:
  decision: deny
`)
		root := writeFile(t, dir, "root.yaml", `version: "0.1"
imports:
  - base.yaml
redaction:
  enabled: true
audit:
  include_redacted_arguments: true
`)
		p, err := LoadFile(root)
		if err != nil {
			t.Fatalf("LoadFile error: %v", err)
		}
		if !p.Redaction.Enabled {
			t.Error("redaction.enabled should be true (importer enabled it)")
		}
		if !p.Audit.IncludeRedactedArguments {
			t.Error("audit.include_redacted_arguments should be true (importer enabled it)")
		}
	})
}

// Scalar fields follow importer-wins: the importing file's non-empty version
// and defaults.decision override the imported file's, while a field the
// importer omits is inherited from the import.
func TestPolicyImportsImporterWinsScalars(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "base.yaml", `version: "base-version"
defaults:
  decision: allow
audit:
  format: jsonl
`)
	root := writeFile(t, dir, "root.yaml", `version: "root-version"
imports:
  - base.yaml
defaults:
  decision: deny
`)
	p, err := LoadFile(root)
	if err != nil {
		t.Fatalf("LoadFile error: %v", err)
	}
	if p.Version != "root-version" {
		t.Errorf("version: importer should win; got %q want %q", p.Version, "root-version")
	}
	if p.Defaults.Decision != DecisionDeny {
		t.Errorf("defaults.decision: importer should win; got %q want %q", p.Defaults.Decision, DecisionDeny)
	}
	if p.Audit.Format != "jsonl" {
		t.Errorf("audit.format: should be inherited from base; got %q want %q", p.Audit.Format, "jsonl")
	}
}
