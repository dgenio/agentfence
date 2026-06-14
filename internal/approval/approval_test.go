package approval

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/dgenio/agentfence/internal/policy"
)

func TestDenyAllApprover(t *testing.T) {
	approved, err := DenyAllApprover{}.Request(context.Background(), policy.ToolCall{ID: "c1", Tool: "filesystem.write"})
	if err != nil {
		t.Fatalf("Request() error = %v", err)
	}
	if approved {
		t.Fatal("DenyAllApprover.Request() = true, want false")
	}
}

func TestTTYApproverDecisions(t *testing.T) {
	cases := []struct {
		name     string
		input    string
		approved bool
	}{
		{"lowercase y", "y\n", true},
		{"uppercase Y", "Y\n", true},
		{"yes", "yes\n", true},
		{"YES", "YES\n", true},
		{"yes with spaces", "  yes  \n", true},
		{"lowercase n", "n\n", false},
		{"uppercase N", "N\n", false},
		{"no", "no\n", false},
		{"empty enter", "\n", false},
		{"garbage", "potato\n", false},
		{"eof no newline", "y", true},
		{"eof empty", "", false},
		{"y then extra text", "y extra\n", false}, // strict: only "y"/"yes" alone
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := &bytes.Buffer{}
			a := NewTTYApproverWithIO(strings.NewReader(tc.input), out)
			approved, err := a.Request(context.Background(), policy.ToolCall{ID: "c1", Tool: "filesystem.write"})
			if err != nil {
				t.Fatalf("Request() error = %v", err)
			}
			if approved != tc.approved {
				t.Fatalf("Request(%q) approved = %v, want %v", tc.input, approved, tc.approved)
			}
			if !strings.Contains(out.String(), "approve filesystem.write [c1]?") {
				t.Errorf("prompt missing tool/id; got %q", out.String())
			}
		})
	}
}

func TestTTYApproverTimeout(t *testing.T) {
	out := &bytes.Buffer{}
	// blockingReader never returns from Read until we close done,
	// simulating a user who doesn't type.
	br := newBlockingReader()
	a := NewTTYApproverWithIO(br, out)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()

	approved, err := a.Request(ctx, policy.ToolCall{ID: "c1", Tool: "github.create_issue"})
	close(br.done)
	if approved {
		t.Fatal("expected approved = false on timeout")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected context.DeadlineExceeded, got %v", err)
	}
	if !strings.Contains(out.String(), "approval timeout for [c1] github.create_issue") {
		t.Errorf("missing timeout notice in output; got %q", out.String())
	}
}

func TestTTYApproverContextAlreadyCancelled(t *testing.T) {
	out := &bytes.Buffer{}
	br := newBlockingReader()
	a := NewTTYApproverWithIO(br, out)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	approved, err := a.Request(ctx, policy.ToolCall{ID: "c2", Tool: "shell.exec"})
	close(br.done)
	if approved {
		t.Fatal("expected approved = false when context is already cancelled")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
}

func TestTTYApproverReadErrorBubblesUp(t *testing.T) {
	out := &bytes.Buffer{}
	wantErr := errors.New("device gone")
	a := NewTTYApproverWithIO(errReader{err: wantErr}, out)

	approved, err := a.Request(context.Background(), policy.ToolCall{ID: "c3", Tool: "filesystem.write"})
	if approved {
		t.Fatal("expected approved = false on read error")
	}
	if err == nil || !errors.Is(err, wantErr) {
		t.Fatalf("expected wrapped %v, got %v", wantErr, err)
	}
}

func TestTTYApproverWritePromptError(t *testing.T) {
	wantErr := errors.New("write fail")
	a := NewTTYApproverWithIO(strings.NewReader("y\n"), errWriter{err: wantErr})

	approved, err := a.Request(context.Background(), policy.ToolCall{ID: "c4", Tool: "filesystem.write"})
	if approved {
		t.Fatal("expected approved = false when prompt write fails")
	}
	if err == nil || !errors.Is(err, wantErr) {
		t.Fatalf("expected wrapped %v, got %v", wantErr, err)
	}
}

func TestTTYApproverCloseIsSafeWithoutOpenFile(t *testing.T) {
	a := NewTTYApproverWithIO(strings.NewReader(""), io.Discard)
	if err := a.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
}

// TestTTYApproverTimeoutThenLateResponse verifies that when a Request times out
// while the operator has not yet typed, the parked read is reused by the next
// Request rather than being lost or raced by a second reader on the same fd. A
// keystroke that arrives after the first prompt times out is consumed by the
// following prompt.
func TestTTYApproverTimeoutThenLateResponse(t *testing.T) {
	pr, pw := io.Pipe()
	defer pw.Close()
	out := &bytes.Buffer{}
	a := NewTTYApproverWithIO(pr, out)

	// First prompt: no input yet, so it times out and denies. Its read
	// goroutine stays parked on the pipe.
	ctx1, cancel1 := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel1()
	if approved, err := a.Request(ctx1, policy.ToolCall{ID: "c1", Tool: "shell.exec"}); approved || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("first Request = (%v, %v), want (false, DeadlineExceeded)", approved, err)
	}

	// The operator now types "y"; the parked reader consumes it, so the second
	// prompt must observe the approval rather than spawning a competing reader.
	go func() { _, _ = pw.Write([]byte("y\n")) }()

	ctx2, cancel2 := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel2()
	approved, err := a.Request(ctx2, policy.ToolCall{ID: "c2", Tool: "shell.exec"})
	if err != nil {
		t.Fatalf("second Request error = %v", err)
	}
	if !approved {
		t.Fatal("expected the late keystroke to approve the second prompt")
	}
}

// blockingReader implements io.Reader and blocks until done is closed,
// allowing the test goroutine to unblock it deterministically after the
// timeout/cancel path is exercised.
type blockingReader struct {
	done chan struct{}
}

func newBlockingReader() *blockingReader {
	return &blockingReader{done: make(chan struct{})}
}

func (b *blockingReader) Read(_ []byte) (int, error) {
	<-b.done
	return 0, io.EOF
}

type errReader struct{ err error }

func (e errReader) Read(_ []byte) (int, error) { return 0, e.err }

type errWriter struct{ err error }

func (e errWriter) Write(_ []byte) (int, error) { return 0, e.err }
