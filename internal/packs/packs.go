// Package packs ships curated, versioned policy packs for the common tool
// surfaces an agent is most likely to touch (filesystem, GitHub, shell).
//
// A pack is an ordinary AgentFence policy document: it is valid on its own and
// composes via the standard `imports:` mechanism, so adopters get a safe
// default for a tool surface without authoring policy from scratch and can
// override any rule by redeclaring the tool key in an importing policy.
//
// The packs (and a matching `agentfence policy test` fixture per pack) are
// embedded into the binary so `agentfence init --pack <names>` can scaffold
// from them offline. The fixtures double as the pack's regression coverage —
// see packs_test.go, which runs every fixture through the engine.
package packs

import (
	"embed"
	"fmt"
	"sort"
)

//go:embed data/*.yaml
var data embed.FS

// names lists the shipped packs. Keep this in sync with the data/ files; the
// test in packs_test.go fails if a pack file has no entry here (or vice versa).
var names = []string{"filesystem", "github", "shell"}

// Names returns the available pack names in sorted order.
func Names() []string {
	out := append([]string(nil), names...)
	sort.Strings(out)
	return out
}

// Exists reports whether name is a known pack.
func Exists(name string) bool {
	for _, n := range names {
		if n == name {
			return true
		}
	}
	return false
}

// Policy returns the policy YAML for the named pack. The boolean is false when
// the pack does not exist.
func Policy(name string) ([]byte, bool) {
	return read(name + ".yaml")
}

// Fixture returns the `agentfence policy test` fixture YAML for the named pack.
// The boolean is false when the pack does not exist.
func Fixture(name string) ([]byte, bool) {
	return read(name + "-tests.yaml")
}

func read(file string) ([]byte, bool) {
	b, err := data.ReadFile("data/" + file)
	if err != nil {
		return nil, false
	}
	return b, true
}

// embeddedFiles returns the names of every embedded data file. Used by tests to
// detect packs that ship a file but are missing from the names list.
func embeddedFiles() ([]string, error) {
	entries, err := data.ReadDir("data")
	if err != nil {
		return nil, fmt.Errorf("packs: read embedded data dir: %w", err)
	}
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		out = append(out, e.Name())
	}
	return out, nil
}
