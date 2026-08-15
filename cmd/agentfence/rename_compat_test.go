package main

import (
	"strings"
	"testing"
)

// These cases pin the bounded dual-read/single-write migration contract from
// #242/#243: the new VeriCordon variable is preferred, the historical
// AgentFence variable remains readable during migration, and ambiguity fails
// closed instead of silently choosing one credential.
func lookupFrom(values map[string]string) envLookup {
	return func(key string) (string, bool) {
		value, ok := values[key]
		return value, ok
	}
}

func TestResolveProxyAuthTokenFlagWins(t *testing.T) {
	got, err := resolveProxyAuthToken("from-flag", lookupFrom(map[string]string{
		preferredProxyAuthEnv: "new-env",
		legacyProxyAuthEnv:    "legacy-env",
	}))
	if err != nil {
		t.Fatalf("resolveProxyAuthToken() error = %v", err)
	}
	if got.Token != "from-flag" {
		t.Fatalf("Token = %q, want flag value", got.Token)
	}
	if got.Warning != "" {
		t.Fatalf("Warning = %q, want none when explicit flag wins", got.Warning)
	}
}

func TestResolveProxyAuthTokenPreferredOnly(t *testing.T) {
	got, err := resolveProxyAuthToken("", lookupFrom(map[string]string{
		preferredProxyAuthEnv: "preferred-secret",
	}))
	if err != nil {
		t.Fatalf("resolveProxyAuthToken() error = %v", err)
	}
	if got.Token != "preferred-secret" || got.Warning != "" {
		t.Fatalf("resolution = %#v, want preferred token without warning", got)
	}
}

func TestResolveProxyAuthTokenLegacyOnlyWarns(t *testing.T) {
	got, err := resolveProxyAuthToken("", lookupFrom(map[string]string{
		legacyProxyAuthEnv: "legacy-secret",
	}))
	if err != nil {
		t.Fatalf("resolveProxyAuthToken() error = %v", err)
	}
	if got.Token != "legacy-secret" {
		t.Fatalf("Token = %q, want legacy token", got.Token)
	}
	if !strings.Contains(got.Warning, legacyProxyAuthEnv) || !strings.Contains(got.Warning, preferredProxyAuthEnv) {
		t.Fatalf("Warning = %q, want migration warning naming both variables", got.Warning)
	}
}

func TestResolveProxyAuthTokenBothEqualWarnsOnce(t *testing.T) {
	got, err := resolveProxyAuthToken("", lookupFrom(map[string]string{
		preferredProxyAuthEnv: "same-secret",
		legacyProxyAuthEnv:    "same-secret",
	}))
	if err != nil {
		t.Fatalf("resolveProxyAuthToken() error = %v", err)
	}
	if got.Token != "same-secret" {
		t.Fatalf("Token = %q, want shared token", got.Token)
	}
	if got.Warning == "" {
		t.Fatal("Warning is empty, want migration warning")
	}
}

func TestResolveProxyAuthTokenConflictFailsClosed(t *testing.T) {
	got, err := resolveProxyAuthToken("", lookupFrom(map[string]string{
		preferredProxyAuthEnv: "new-secret",
		legacyProxyAuthEnv:    "different-secret",
	}))
	if err == nil {
		t.Fatal("resolveProxyAuthToken() error = nil, want fail-closed conflict")
	}
	if got.Token != "" {
		t.Fatalf("Token = %q, want no selected credential on conflict", got.Token)
	}
	if !strings.Contains(err.Error(), preferredProxyAuthEnv) || !strings.Contains(err.Error(), legacyProxyAuthEnv) {
		t.Fatalf("error = %q, want both variable names", err)
	}
}

func TestResolveProxyAuthTokenEmptyValuesAreAbsent(t *testing.T) {
	got, err := resolveProxyAuthToken("", lookupFrom(map[string]string{
		preferredProxyAuthEnv: "",
		legacyProxyAuthEnv:    "",
	}))
	if err != nil {
		t.Fatalf("resolveProxyAuthToken() error = %v", err)
	}
	if got.Token != "" || got.Warning != "" {
		t.Fatalf("resolution = %#v, want empty", got)
	}
}

func TestResolveProxyAuthTokenPreservesCredentialBytes(t *testing.T) {
	const token = "  secret-with-spaces  "
	got, err := resolveProxyAuthToken("", lookupFrom(map[string]string{
		preferredProxyAuthEnv: token,
	}))
	if err != nil {
		t.Fatalf("resolveProxyAuthToken() error = %v", err)
	}
	if got.Token != token {
		t.Fatalf("Token = %q, want exact %q", got.Token, token)
	}
}

func TestResolveProxyAuthTokenRequiresLookupWithoutFlag(t *testing.T) {
	got, err := resolveProxyAuthToken("", nil)
	if err == nil {
		t.Fatal("resolveProxyAuthToken() error = nil, want error when lookup is unavailable")
	}
	if got.Token != "" {
		t.Fatalf("Token = %q, want empty on lookup error", got.Token)
	}
}
