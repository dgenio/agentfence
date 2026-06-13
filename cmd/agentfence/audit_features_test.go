package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dgenio/agentfence/internal/audit"
)

// writeSigningFixtures writes a minimal allow policy and a one-call input,
// returning their paths plus a fresh audit-log path under a temp dir.
func writeSigningFixtures(t *testing.T) (policyFile, callFile, auditFile, dir string) {
	t.Helper()
	dir = t.TempDir()
	policyFile = filepath.Join(dir, "policy.yaml")
	callFile = filepath.Join(dir, "calls.jsonl")
	auditFile = filepath.Join(dir, "audit.jsonl")
	writeTestFile(t, policyFile, []byte(`version: "0.1"
defaults:
  decision: deny
tools:
  filesystem.read:
    decision: allow
`))
	writeTestFile(t, callFile, []byte(
		`{"id":"c1","tool":"filesystem.read","arguments":{"path":"README.md"}}`+"\n"+
			`{"id":"c2","tool":"filesystem.read","arguments":{"path":"go.mod"}}`+"\n",
	))
	return policyFile, callFile, auditFile, dir
}

func TestAuditKeygenCreatesUsableKeys(t *testing.T) {
	dir := t.TempDir()
	priv := filepath.Join(dir, "audit.key")
	pub := filepath.Join(dir, "audit.pub")
	if err := runAuditKeygen([]string{"--private", priv, "--public", pub}); err != nil {
		t.Fatalf("runAuditKeygen: %v", err)
	}
	info, err := os.Stat(priv)
	if err != nil {
		t.Fatalf("stat private key: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Errorf("private key mode = %o, want 600", got)
	}
	if _, err := audit.LoadPublicKey(pub); err != nil {
		t.Errorf("generated public key did not load: %v", err)
	}
}

func TestAuditKeygenRequiresPaths(t *testing.T) {
	if err := runAuditKeygen([]string{"--private", "only.key"}); err == nil {
		t.Fatal("expected error when --public is missing")
	}
}

func TestCheckSignThenVerifyWithPubkey(t *testing.T) {
	policyFile, callFile, auditFile, dir := writeSigningFixtures(t)
	priv := filepath.Join(dir, "audit.key")
	pub := filepath.Join(dir, "audit.pub")
	if err := runAuditKeygen([]string{"--private", priv, "--public", pub}); err != nil {
		t.Fatalf("keygen: %v", err)
	}

	if err := runCheck([]string{
		"--policy", policyFile, "--call", callFile,
		"--audit-log", auditFile, "--output", "json",
		"--tamper-evident", "--sign-key", priv,
	}); err != nil {
		t.Fatalf("runCheck --sign-key: %v", err)
	}

	stdout, _, err := captureOutput(t, func() error {
		return runAuditVerify([]string{"--log", auditFile, "--pubkey", pub})
	})
	if err != nil {
		t.Fatalf("runAuditVerify --pubkey: %v\n%s", err, stdout)
	}
	if !strings.Contains(stdout, "SIGNATURES: 2 verified, 0 unsigned") {
		t.Fatalf("unexpected verify output: %q", stdout)
	}
}

func TestVerifyWithWrongPubkeyFails(t *testing.T) {
	policyFile, callFile, auditFile, dir := writeSigningFixtures(t)
	priv := filepath.Join(dir, "audit.key")
	pub := filepath.Join(dir, "audit.pub")
	otherPriv := filepath.Join(dir, "other.key")
	otherPub := filepath.Join(dir, "other.pub")
	if err := runAuditKeygen([]string{"--private", priv, "--public", pub}); err != nil {
		t.Fatalf("keygen: %v", err)
	}
	if err := runAuditKeygen([]string{"--private", otherPriv, "--public", otherPub}); err != nil {
		t.Fatalf("keygen other: %v", err)
	}
	if err := runCheck([]string{
		"--policy", policyFile, "--call", callFile,
		"--audit-log", auditFile, "--output", "json", "--sign-key", priv,
	}); err != nil {
		t.Fatalf("runCheck: %v", err)
	}
	// Verify against a key the events were NOT signed with.
	_, _, err := captureOutput(t, func() error {
		return runAuditVerify([]string{"--log", auditFile, "--pubkey", otherPub})
	})
	if err == nil {
		t.Fatal("expected signature verification to fail against the wrong public key")
	}
}

func TestAnchorRoundTripAndTruncationDetection(t *testing.T) {
	auditFile := writeTamperEvidentLog(t) // 3 chained events
	dir := filepath.Dir(auditFile)
	anchorFile := filepath.Join(dir, "anchor.json")

	if _, _, err := captureOutput(t, func() error {
		return runAuditAnchor([]string{"--log", auditFile, "--out", anchorFile})
	}); err != nil {
		t.Fatalf("runAuditAnchor: %v", err)
	}

	// A full log still contains the anchored event.
	stdout, _, err := captureOutput(t, func() error {
		return runAuditVerify([]string{"--log", auditFile, "--anchor", anchorFile})
	})
	if err != nil {
		t.Fatalf("verify --anchor on intact log: %v", err)
	}
	if !strings.Contains(stdout, "ANCHOR: log still contains anchored event") {
		t.Fatalf("unexpected anchor verify output: %q", stdout)
	}

	// Truncate the log to its first event; the anchored final event disappears.
	contents, err := os.ReadFile(auditFile)
	if err != nil {
		t.Fatal(err)
	}
	firstLine := contents[:strings.IndexByte(string(contents), '\n')+1]
	if err := os.WriteFile(auditFile, firstLine, 0o600); err != nil {
		t.Fatal(err)
	}
	_, _, err = captureOutput(t, func() error {
		return runAuditVerify([]string{"--log", auditFile, "--anchor", anchorFile})
	})
	if err == nil {
		t.Fatal("expected anchor verification to fail on a truncated log")
	}
}

func TestVerifySignedAnchorWithPubkey(t *testing.T) {
	auditFile := writeTamperEvidentLog(t) // 3 chained events
	dir := filepath.Dir(auditFile)
	anchorFile := filepath.Join(dir, "anchor.json")
	priv := filepath.Join(dir, "audit.key")
	pub := filepath.Join(dir, "audit.pub")
	otherPub := filepath.Join(dir, "other.pub")
	if err := runAuditKeygen([]string{"--private", priv, "--public", pub}); err != nil {
		t.Fatalf("keygen: %v", err)
	}
	if err := runAuditKeygen([]string{"--private", filepath.Join(dir, "other.key"), "--public", otherPub}); err != nil {
		t.Fatalf("keygen other: %v", err)
	}

	// Produce a signed anchor.
	if _, _, err := captureOutput(t, func() error {
		return runAuditAnchor([]string{"--log", auditFile, "--out", anchorFile, "--sign-key", priv})
	}); err != nil {
		t.Fatalf("runAuditAnchor --sign-key: %v", err)
	}

	// The matching public key authenticates the anchor.
	stdout, _, err := captureOutput(t, func() error {
		return runAuditVerify([]string{"--log", auditFile, "--anchor", anchorFile, "--anchor-pubkey", pub})
	})
	if err != nil {
		t.Fatalf("verify signed anchor with correct anchor-pubkey: %v\n%s", err, stdout)
	}
	if !strings.Contains(stdout, "ANCHOR SIGNATURE: verified") {
		t.Fatalf("expected anchor signature to verify, got: %q", stdout)
	}

	// A different key must make anchor-signature verification fail.
	_, _, err = captureOutput(t, func() error {
		return runAuditVerify([]string{"--log", auditFile, "--anchor", anchorFile, "--anchor-pubkey", otherPub})
	})
	if err == nil {
		t.Fatal("expected anchor signature verification to fail against the wrong anchor public key")
	}
}

func TestAnchorRejectsUnchainedLog(t *testing.T) {
	policyFile, callFile, auditFile, _ := writeSigningFixtures(t)
	// Write a plain (unchained) log.
	if err := runCheck([]string{
		"--policy", policyFile, "--call", callFile,
		"--audit-log", auditFile, "--output", "json",
	}); err != nil {
		t.Fatalf("runCheck: %v", err)
	}
	err := runAuditAnchor([]string{"--log", auditFile})
	if err == nil || !strings.Contains(err.Error(), "tamper-evident") {
		t.Fatalf("expected a tamper-evident hint, got %v", err)
	}
}

func TestCheckRotationProducesVerifiableSegments(t *testing.T) {
	dir := t.TempDir()
	policyFile := filepath.Join(dir, "policy.yaml")
	callFile := filepath.Join(dir, "calls.jsonl")
	auditFile := filepath.Join(dir, "audit.jsonl")
	writeTestFile(t, policyFile, []byte(`version: "0.1"
defaults:
  decision: deny
tools:
  filesystem.read:
    decision: allow
`))
	var b strings.Builder
	for i := 0; i < 30; i++ {
		b.WriteString(`{"id":"c","tool":"filesystem.read","arguments":{"path":"README.md"}}` + "\n")
	}
	writeTestFile(t, callFile, []byte(b.String()))

	if err := runCheck([]string{
		"--policy", policyFile, "--call", callFile,
		"--audit-log", auditFile, "--output", "json",
		"--tamper-evident", "--audit-max-size", "300", "--audit-keep", "20",
	}); err != nil {
		t.Fatalf("runCheck with rotation: %v", err)
	}

	segments, err := filepath.Glob(auditFile + ".*")
	if err != nil {
		t.Fatal(err)
	}
	if len(segments) == 0 {
		t.Fatal("expected at least one rotated segment")
	}
	// Every rotated segment must verify independently.
	for _, seg := range segments {
		if _, _, err := captureOutput(t, func() error {
			return runAuditVerify([]string{"--log", seg})
		}); err != nil {
			t.Errorf("rotated segment %s failed verification: %v", seg, err)
		}
	}
}

func TestRotationFlagsRequireAuditLog(t *testing.T) {
	policyFile, callFile, _, _ := writeSigningFixtures(t)
	err := runCheck([]string{
		"--policy", policyFile, "--call", callFile,
		"--audit-max-size", "100",
	})
	if err == nil || !strings.Contains(err.Error(), "require --audit-log") {
		t.Fatalf("expected require --audit-log error, got %v", err)
	}
}
