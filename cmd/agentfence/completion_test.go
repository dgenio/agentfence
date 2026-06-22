package main

import (
	"bytes"
	"strings"
	"testing"
)

// TestTopLevelCommandsMatchDispatch guards against drift: every command offered
// to completions/man must be routable by runRoot, and every routable command
// (besides the help pseudo-commands) must be documented here.
func TestTopLevelCommandsMatchDispatch(t *testing.T) {
	// The authoritative dispatch set from runRoot's switch.
	want := map[string]bool{
		"audit": true, "check": true, "completion": true, "demo": true,
		"explain": true, "init": true, "man": true, "policy": true,
		"proxy": true, "proxy-http": true, "validate": true, "version": true,
	}
	got := map[string]bool{}
	for _, c := range topLevelCommands {
		if got[c.Name] {
			t.Fatalf("duplicate command %q in topLevelCommands", c.Name)
		}
		got[c.Name] = true
		if c.Summary == "" {
			t.Errorf("command %q has an empty summary", c.Name)
		}
	}
	for name := range want {
		if !got[name] {
			t.Errorf("dispatch command %q is missing from topLevelCommands (completions/man would omit it)", name)
		}
	}
	for name := range got {
		if !want[name] {
			t.Errorf("topLevelCommands lists %q which runRoot does not dispatch", name)
		}
	}
}

// TestSubcommandGroupsMatchDispatch extends the drift guard to the second
// level: every group in subcommandGroups must list exactly the subcommands its
// dispatcher routes (runAuditSubcmd / runPolicySubcmd switches, and the
// completion shells). Without this, adding e.g. a new `audit` subcommand would
// silently drop it from completions with no failing test.
func TestSubcommandGroupsMatchDispatch(t *testing.T) {
	// Authoritative subcommand sets, mirroring the dispatch switches in main.go
	// (runAuditSubcmd, runPolicySubcmd) and the completion shell list.
	want := map[string][]string{
		"audit":      {"verify", "summarize", "export", "keygen", "anchor"},
		"policy":     {"test", "validate"},
		"completion": supportedShells,
	}
	if len(subcommandGroups) != len(want) {
		t.Errorf("subcommandGroups has %d groups, want %d (%v vs %v)",
			len(subcommandGroups), len(want), groupKeys(subcommandGroups), groupKeys(want))
	}
	for group, wantSubs := range want {
		gotSubs, ok := subcommandGroups[group]
		if !ok {
			t.Errorf("subcommandGroups is missing group %q (dispatch routes it but completions would omit it)", group)
			continue
		}
		if !equalStringSets(gotSubs, wantSubs) {
			t.Errorf("subcommandGroups[%q] = %v, want %v (dispatch and completions have drifted)", group, gotSubs, wantSubs)
		}
	}
	for group := range subcommandGroups {
		if _, ok := want[group]; !ok {
			t.Errorf("subcommandGroups lists group %q which no dispatcher routes", group)
		}
	}
}

// groupKeys returns the keys of a subcommand-group map, for diagnostics.
func groupKeys(m map[string][]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

// equalStringSets reports whether a and b contain the same elements, ignoring
// order (subcommandGroups is order-significant for output, but drift detection
// is about membership).
func equalStringSets(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	seen := make(map[string]int, len(a))
	for _, s := range a {
		seen[s]++
	}
	for _, s := range b {
		seen[s]--
	}
	for _, n := range seen {
		if n != 0 {
			return false
		}
	}
	return true
}

func TestWriteCompletionContainsCommands(t *testing.T) {
	for _, shell := range supportedShells {
		shell := shell
		t.Run(shell, func(t *testing.T) {
			var buf bytes.Buffer
			if err := writeCompletion(&buf, shell); err != nil {
				t.Fatalf("writeCompletion(%s) error: %v", shell, err)
			}
			out := buf.String()
			if out == "" {
				t.Fatalf("writeCompletion(%s) produced no output", shell)
			}
			// Every top-level command name must appear in the script.
			for _, c := range topLevelCommands {
				if !strings.Contains(out, c.Name) {
					t.Errorf("%s completion is missing command %q", shell, c.Name)
				}
			}
			// Subcommand groups must be offered too.
			if !strings.Contains(out, "summarize") || !strings.Contains(out, "keygen") {
				t.Errorf("%s completion is missing audit subcommands", shell)
			}
		})
	}
}

func TestWriteCompletionShellMarkers(t *testing.T) {
	cases := map[string]string{
		"bash": "complete -F _agentfence agentfence",
		"zsh":  "#compdef agentfence",
		"fish": "complete -c agentfence",
	}
	for shell, marker := range cases {
		var buf bytes.Buffer
		if err := writeCompletion(&buf, shell); err != nil {
			t.Fatalf("writeCompletion(%s) error: %v", shell, err)
		}
		if !strings.Contains(buf.String(), marker) {
			t.Errorf("%s completion missing expected marker %q", shell, marker)
		}
	}
}

func TestWriteCompletionUnsupportedShell(t *testing.T) {
	var buf bytes.Buffer
	err := writeCompletion(&buf, "powershell")
	if err == nil {
		t.Fatal("expected an error for an unsupported shell")
	}
	if !strings.Contains(err.Error(), "unsupported shell") {
		t.Fatalf("error = %v, want unsupported shell", err)
	}
}

func TestRunCompletionArgCount(t *testing.T) {
	if err := runCompletion(nil); err == nil {
		t.Error("completion with no shell argument should error")
	}
	if err := runCompletion([]string{"bash", "zsh"}); err == nil {
		t.Error("completion with two arguments should error")
	}
}

func TestWriteManPage(t *testing.T) {
	var buf bytes.Buffer
	if err := writeManPage(&buf); err != nil {
		t.Fatalf("writeManPage error: %v", err)
	}
	out := buf.String()
	for _, want := range []string{".TH AGENTFENCE 1", ".SH NAME", ".SH COMMANDS", "agentfence \\- policy firewall"} {
		if !strings.Contains(out, want) {
			t.Errorf("man page missing %q", want)
		}
	}
	for _, c := range topLevelCommands {
		if !strings.Contains(out, c.Name) {
			t.Errorf("man page missing command %q", c.Name)
		}
	}
}

func TestRunManRejectsArgs(t *testing.T) {
	if err := runMan([]string{"extra"}); err == nil {
		t.Error("man should reject positional arguments")
	}
}

// TestZshCompletionDispatch locks in the subcommand-dispatch structure. With
// the '*::' rest-args spec, zsh rescopes $words so $words[1] is the subcommand
// (verified empirically: `audit <TAB>` => $words[1]=audit). Switching to
// $words[2] would break group completion, so guard against that regression.
func TestZshCompletionDispatch(t *testing.T) {
	var buf bytes.Buffer
	if err := writeZshCompletion(&buf); err != nil {
		t.Fatalf("writeZshCompletion error: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "case $words[1] in") {
		t.Errorf("zsh completion must dispatch subcommands on $words[1]; got:\n%s", out)
	}
	if strings.Contains(out, "case $words[2] in") {
		t.Error("zsh completion must not dispatch on $words[2] (empty in the '*::' rest state)")
	}
	for name := range subcommandGroups {
		if !strings.Contains(out, name+") _values") {
			t.Errorf("zsh completion missing _values dispatch for group %q", name)
		}
	}
}

// TestBashCompletionDispatch confirms bash dispatches subcommands at word 2
// (COMP_CWORD -eq 2), where COMP_WORDS[1] holds the chosen command.
func TestBashCompletionDispatch(t *testing.T) {
	var buf bytes.Buffer
	if err := writeBashCompletion(&buf); err != nil {
		t.Fatalf("writeBashCompletion error: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "COMP_CWORD} -eq 2") || !strings.Contains(out, "${COMP_WORDS[1]}") {
		t.Errorf("bash completion should dispatch group subcommands on COMP_WORDS[1] at depth 2; got:\n%s", out)
	}
}

func TestManEscape(t *testing.T) {
	cases := map[string]string{
		"plain text":    "plain text",
		".leading dot":  `\&.leading dot`,
		"'leading tick": `\&'leading tick`,
		`back\slash`:    `back\\slash`,
	}
	for in, want := range cases {
		if got := manEscape(in); got != want {
			t.Errorf("manEscape(%q) = %q, want %q", in, got, want)
		}
	}
}
