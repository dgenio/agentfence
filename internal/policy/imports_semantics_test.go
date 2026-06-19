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

// Scalar fields follow importer-wins when the importer sets them explicitly.
func TestPolicyImportsImporterWinsScalars(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "base.yaml", `version: "base-version"
defaults:
  decision: allow
`)
	root := writeFile(t, dir, "root.yaml", `version: "root-version"
imports:
  - base.yaml
defaults:
  decision: ask
`)
	p, err := LoadFile(root)
	if err != nil {
		t.Fatalf("LoadFile error: %v", err)
	}
	if p.Version != "root-version" {
		t.Errorf("version: importer should win; got %q want %q", p.Version, "root-version")
	}
	if p.Defaults.Decision != DecisionAsk {
		t.Errorf("defaults.decision: importer should win; got %q want %q", p.Defaults.Decision, DecisionAsk)
	}
}

// When the importer *omits* a scalar, the behavior depends on whether the field
// has a per-file default. ParsePolicy applies defaults (defaults.decision→deny,
// audit.format→jsonl) to every file *before* imports are merged, so omitting
// those in the importer is equivalent to setting them to their default — the
// filled-in value wins over the base and the base value does NOT shine through.
// `version` has no per-file default, so it is the one scalar that truly
// inherits from the base when omitted. See docs/policy-language.md
// ("Policy imports") for the contract this pins.
func TestPolicyImportsOmittedScalarsUsePerFileDefaults(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "base.yaml", `version: "base-version"
defaults:
  decision: allow
`)
	// root omits both version and defaults.decision.
	root := writeFile(t, dir, "root.yaml", `imports:
  - base.yaml
tools:
  root.tool:
    decision: deny
`)
	p, err := LoadFile(root)
	if err != nil {
		t.Fatalf("LoadFile error: %v", err)
	}
	if p.Version != "base-version" {
		t.Errorf("version: should inherit from base when omitted (no per-file default); got %q want %q", p.Version, "base-version")
	}
	// The base says allow, but the importer's per-file default (deny) is applied
	// before merge and overrides it — omission does not inherit the base here.
	if p.Defaults.Decision != DecisionDeny {
		t.Errorf("defaults.decision: omitted importer field should resolve to the per-file default deny, not inherit base allow; got %q", p.Defaults.Decision)
	}
}
