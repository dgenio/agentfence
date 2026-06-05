package packs

import (
	"strings"
	"testing"

	"github.com/dgenio/agentfence/internal/engine"
	"github.com/dgenio/agentfence/internal/policy"
)

// TestEveryEmbeddedFileHasPackEntry guards against a pack file being added to
// data/ without being registered in names (or a -tests fixture going missing).
func TestEveryEmbeddedFileHasPackEntry(t *testing.T) {
	files, err := embeddedFiles()
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, f := range files {
		got[f] = true
	}
	for _, name := range names {
		if !got[name+".yaml"] {
			t.Errorf("pack %q registered in names but data/%s.yaml is missing", name, name)
		}
		if !got[name+"-tests.yaml"] {
			t.Errorf("pack %q has no fixture data/%s-tests.yaml", name, name)
		}
	}
	// Every policy .yaml that is not a -tests fixture must be a registered pack.
	for _, f := range files {
		if strings.HasSuffix(f, "-tests.yaml") {
			continue
		}
		name := strings.TrimSuffix(f, ".yaml")
		if !Exists(name) {
			t.Errorf("data/%s ships a policy but %q is not registered in names", f, name)
		}
	}
}

// TestPacksParseAndValidate verifies each pack is a well-formed policy.
func TestPacksParseAndValidate(t *testing.T) {
	for _, name := range Names() {
		t.Run(name, func(t *testing.T) {
			body, ok := Policy(name)
			if !ok {
				t.Fatalf("Policy(%q) not found", name)
			}
			if errs := policy.ValidateStrict(body); len(errs) > 0 {
				t.Fatalf("pack %q failed strict validation: %v", name, errs)
			}
			if _, err := policy.ParsePolicy(body); err != nil {
				t.Fatalf("pack %q failed to parse: %v", name, err)
			}
		})
	}
}

// TestPackFixtures runs each pack's shipped fixture through the engine, the same
// way `agentfence policy test` does, asserting every decision matches.
func TestPackFixtures(t *testing.T) {
	for _, name := range Names() {
		t.Run(name, func(t *testing.T) {
			body, ok := Policy(name)
			if !ok {
				t.Fatalf("Policy(%q) not found", name)
			}
			p, err := policy.ParsePolicy(body)
			if err != nil {
				t.Fatalf("parse pack %q: %v", name, err)
			}
			eng, err := engine.New(p)
			if err != nil {
				t.Fatalf("engine for pack %q: %v", name, err)
			}

			fb, ok := Fixture(name)
			if !ok {
				t.Fatalf("Fixture(%q) not found", name)
			}
			fixture, err := policy.ParsePolicyTestFixture(fb)
			if err != nil {
				t.Fatalf("parse fixture %q: %v", name, err)
			}
			if len(fixture.Tests) == 0 {
				t.Fatalf("pack %q fixture has no tests", name)
			}

			for _, tc := range fixture.Tests {
				args := tc.Arguments
				if args == nil {
					args = map[string]interface{}{}
				}
				res, _ := eng.Evaluate(policy.ToolCall{ID: tc.ID, Tool: tc.Tool, Arguments: args})
				if res.Decision != tc.Expect {
					t.Errorf("%s/%s: decision = %s, want %s (reason: %s)", name, tc.ID, res.Decision, tc.Expect, res.Reason)
				}
			}
		})
	}
}
