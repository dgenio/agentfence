package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestCheckAuditFsyncProducesVerifiableLog runs the full check path with
// --audit-fsync and --tamper-evident and confirms the resulting log is complete
// and verifies, exercising the durability plumbing end to end (#132).
func TestCheckAuditFsyncProducesVerifiableLog(t *testing.T) {
	policyFile, callFile, auditFile, _ := writeSigningFixtures(t)

	if err := runCheck([]string{
		"--policy", policyFile, "--call", callFile,
		"--audit-log", auditFile, "--output", "json",
		"--tamper-evident", "--audit-fsync",
	}); err != nil {
		t.Fatalf("runCheck --audit-fsync: %v", err)
	}

	stdout, _, err := captureOutput(t, func() error {
		return runAuditVerify([]string{"--log", auditFile})
	})
	if err != nil {
		t.Fatalf("runAuditVerify: %v\n%s", err, stdout)
	}
	if !strings.Contains(stdout, "OK: 2 event(s) verified") {
		t.Fatalf("unexpected verify output: %q", stdout)
	}
}

// TestCheckAuditFsyncWithoutLogDoesNotFail guards against --audit-fsync turning
// into a fatal Sync() on a TTY/pipe stdout when no --audit-log is given: the
// flag must degrade to a no-op (with a warning), not fail the run. captureOutput
// redirects stdout to an os.Pipe, so a stray fsync on stdout would surface here.
func TestCheckAuditFsyncWithoutLogDoesNotFail(t *testing.T) {
	policyFile, callFile, _, _ := writeSigningFixtures(t)

	_, stderr, err := captureOutput(t, func() error {
		return runCheck([]string{
			"--policy", policyFile, "--call", callFile,
			"--output", "text", "--audit-fsync",
		})
	})
	if err != nil {
		t.Fatalf("runCheck --audit-fsync without --audit-log: %v", err)
	}
	if !strings.Contains(stderr, "--audit-fsync has no effect without --audit-log") {
		t.Fatalf("expected a no-effect warning on stderr, got: %q", stderr)
	}
}

// TestVerifyReportsCorruptInput confirms `audit verify` reports a damaged,
// unparseable log as CORRUPT (distinct from a tamper FAILED) and exits non-zero
// (#180).
func TestVerifyReportsCorruptInput(t *testing.T) {
	logFile := filepath.Join(t.TempDir(), "audit.jsonl")
	writeTestFile(t, logFile, []byte("{this is not json\n"))

	stdout, _, err := captureOutput(t, func() error {
		return runAuditVerify([]string{"--log", logFile})
	})
	if err == nil {
		t.Fatal("expected verify to fail on a corrupt log")
	}
	if !strings.Contains(stdout, "CORRUPT") {
		t.Fatalf("expected a CORRUPT status line, got: %q", stdout)
	}
}

// TestVerifyReportsTamper confirms `audit verify` reports an integrity break in
// a chained log as FAILED, not CORRUPT (#180).
func TestVerifyReportsTamper(t *testing.T) {
	policyFile, callFile, auditFile, _ := writeSigningFixtures(t)
	if err := runCheck([]string{
		"--policy", policyFile, "--call", callFile,
		"--audit-log", auditFile, "--output", "json", "--tamper-evident",
	}); err != nil {
		t.Fatalf("runCheck: %v", err)
	}

	raw, err := os.ReadFile(auditFile)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	// Corrupt the claimed hash of the first event but keep the line valid JSON:
	// the recompute will mismatch, an integrity break rather than a parse error.
	tampered := strings.Replace(string(raw), `"hash":"`, `"hash":"0`, 1)
	writeTestFile(t, auditFile, []byte(tampered))

	stdout, _, err := captureOutput(t, func() error {
		return runAuditVerify([]string{"--log", auditFile})
	})
	if err == nil {
		t.Fatal("expected verify to fail on a tampered log")
	}
	if !strings.Contains(stdout, "FAILED") {
		t.Fatalf("expected a FAILED status line, got: %q", stdout)
	}
	if strings.Contains(stdout, "CORRUPT") {
		t.Fatalf("tampering must not be reported as CORRUPT: %q", stdout)
	}
}
