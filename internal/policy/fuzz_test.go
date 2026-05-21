package policy

import "testing"

// FuzzParsePolicy feeds arbitrary bytes to ParsePolicy and asserts that the
// parser never panics. ParsePolicy is reached by the validate, check, explain,
// proxy, and policy test/validate commands on operator-supplied YAML; a panic
// here would crash the binary on a malformed user input.
func FuzzParsePolicy(f *testing.F) {
	f.Add([]byte(StarterPolicyYAML))
	f.Add([]byte(""))
	f.Add([]byte("\n"))
	f.Add([]byte("version: \"0.1\"\ndefaults:\n  decision: allow\n"))
	f.Add([]byte("version: \"0.1\"\ndefaults:\n  decision: bogus\n"))
	f.Add([]byte("not: yaml: at: all"))
	// Deeply nested mapping that exercises the YAML decoder.
	f.Add([]byte("a:\n  b:\n    c:\n      d:\n        e: 1\n"))
	// Imports key with nonsense values to stress the (future) import resolver
	// shape; today this is just round-tripped through KnownFields.
	f.Add([]byte("imports:\n  - 1\n  - {}\n"))

	f.Fuzz(func(t *testing.T, data []byte) {
		// We only care about no-panic. Errors are an acceptable outcome for
		// arbitrary input.
		_, _ = ParsePolicy(data)
	})
}

// FuzzParseToolCall feeds arbitrary bytes to ParseToolCall and asserts that
// the parser never panics. ParseToolCall runs on every JSONL line in the
// check command's input stream, which originates from agents and can be
// crafted by an attacker if the upstream agent is compromised.
func FuzzParseToolCall(f *testing.F) {
	f.Add([]byte(`{"id":"c","tool":"filesystem.read","arguments":{"path":"README.md"}}`))
	f.Add([]byte(`{}`))
	f.Add([]byte(``))
	f.Add([]byte(`not json`))
	f.Add([]byte(`{"id":"c","tool":"filesystem.read","arguments":null}`))
	f.Add([]byte(`{"id":"c","tool":"x","arguments":{"a":{"b":{"c":{"d":1}}}}}`))
	// Empty tool name and empty arguments map.
	f.Add([]byte(`{"id":"","tool":"","arguments":{}}`))

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = ParseToolCall(data)
	})
}
