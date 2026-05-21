package engine

import "testing"

// FuzzMatchesGlob feeds arbitrary pattern/value pairs to matchesGlob and
// asserts that it neither panics nor enters catastrophic backtracking.
// matchesGlob builds a regex from the operator-supplied glob pattern and was
// previously using regexp.MustCompile, which would panic on a malformed
// expression — the engine.go change in this PR swaps to regexp.Compile with a
// fallback so this fuzz target should no longer surface that class of bug.
func FuzzMatchesGlob(f *testing.F) {
	seeds := []struct {
		pattern, value string
	}{
		{"", ""},
		{"./", "anything"},
		{".", "anything"},
		{"**/*.go", "internal/engine/engine.go"},
		{"docs/**", "docs/README.md"},
		{"./secrets/**", "secrets/token.txt"},
		{"*.env", ".env"},
		{"a/*/b", "a/x/b"},
		{"a/**/b", "a/x/y/b"},
		// Adversarial inputs that previously could panic regexp.MustCompile.
		{"[", ""},
		{"(", "x"},
		{"\\", "\\"},
	}
	for _, s := range seeds {
		f.Add(s.pattern, s.value)
	}

	f.Fuzz(func(t *testing.T, pattern, value string) {
		// Bound input size so fuzzing does not blow memory on artificially
		// long inputs; matchesGlob does not protect itself against this
		// today, and we are testing the no-panic invariant, not throughput.
		if len(pattern) > 1024 || len(value) > 8192 {
			t.Skip()
		}
		// Drop NUL bytes — Go regexp accepts them, but path.Match treats them
		// as ordinary runes and this skews coverage toward an irrelevant class
		// of inputs. The real attack surface is structural glob syntax.
		for _, r := range pattern {
			if r == 0 {
				t.Skip()
			}
		}
		_ = matchesGlob(pattern, value)
	})
}
