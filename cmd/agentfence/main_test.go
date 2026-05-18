package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRunCheckRequiresFlags(t *testing.T) {
	err := runCheck([]string{})
	if err == nil {
		t.Fatal("expected error when --policy and --call are missing")
	}
}

func TestRunCheckWithValidInput(t *testing.T) {
	dir := t.TempDir()
	policyFile := filepath.Join(dir, "policy.yaml")
	callFile := filepath.Join(dir, "calls.jsonl")

	policyContent := `version: "0.1"
defaults:
  decision: deny
tools:
  filesystem.read:
    decision: allow
`
	if err := os.WriteFile(policyFile, []byte(policyContent), 0o644); err != nil {
		t.Fatal(err)
	}

	callContent := `{"id":"call_1","tool":"filesystem.read","arguments":{"path":"README.md"}}
`
	if err := os.WriteFile(callFile, []byte(callContent), 0o644); err != nil {
		t.Fatal(err)
	}

	err := runCheck([]string{"--policy", policyFile, "--call", callFile})
	if err != nil {
		t.Fatalf("runCheck() error = %v", err)
	}
}

func TestRunInitCreatesFile(t *testing.T) {
	dir := t.TempDir()
	orig, _ := os.Getwd()
	defer os.Chdir(orig)
	os.Chdir(dir)

	err := runInit()
	if err != nil {
		t.Fatalf("runInit() error = %v", err)
	}

	if _, err := os.Stat(filepath.Join(dir, "agentfence.yaml")); os.IsNotExist(err) {
		t.Fatal("expected agentfence.yaml to be created")
	}
}

func TestRunInitFailsIfFileExists(t *testing.T) {
	dir := t.TempDir()
	orig, _ := os.Getwd()
	defer os.Chdir(orig)
	os.Chdir(dir)

	os.WriteFile("agentfence.yaml", []byte("existing"), 0o644)

	err := runInit()
	if err == nil {
		t.Fatal("expected error when file already exists")
	}
}
