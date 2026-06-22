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
