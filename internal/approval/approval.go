// Package approval converts policy ask decisions into a final allow/deny.
//
// The Approver interface is the single integration point that the check
// command and both proxies (internal/proxy, internal/httpproxy) use to
// interact with an operator. Implementations must be safe to call
// concurrently from goroutines that forward different tool calls, but a single
// call to Request is expected to be sequential.
package approval

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/dgenio/agentfence/internal/policy"
)

const ReasonApprovedInteractively = "approved interactively"
const ReasonDeniedInteractively = "denied interactively"
const ReasonApprovalTimeout = "approval timeout"
const ReasonApprovalCancelled = "approval cancelled"
const ReasonApprovalIOError = "approval I/O error"
const ReasonNonInteractive = "non-interactive: ask auto-denied"

type Approver interface {
	Request(ctx context.Context, call policy.ToolCall) (bool, error)
}

type DenyAllApprover struct{}

func (DenyAllApprover) Request(_ context.Context, _ policy.ToolCall) (bool, error) {
	return false, nil
}

type Outcome struct {
	Approved bool
	Reason   string
	Code     policy.ReasonCode
}

func Resolve(ctx context.Context, approver Approver, call policy.ToolCall, timeout time.Duration, noInteractive bool) (Outcome, error) {
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}

	approved, err := approver.Request(ctx, call)
	switch {
	case approved:
		return Outcome{Approved: true, Reason: ReasonApprovedInteractively, Code: policy.ReasonCodeApprovalApproved}, err
	case errors.Is(err, context.DeadlineExceeded):
		return Outcome{Reason: ReasonApprovalTimeout, Code: policy.ReasonCodeApprovalTimeout}, err
	case errors.Is(err, context.Canceled):
		return Outcome{Reason: ReasonApprovalCancelled, Code: policy.ReasonCodeApprovalCancelled}, err
	case err != nil:
		return Outcome{Reason: ReasonApprovalIOError, Code: policy.ReasonCodeApprovalIOError}, err
	case noInteractive:
		return Outcome{Reason: ReasonNonInteractive, Code: policy.ReasonCodeNonInteractive}, nil
	default:
		return Outcome{Reason: ReasonDeniedInteractively, Code: policy.ReasonCodeApprovalDenied}, nil
	}
}

type TTYApprover struct {
	mu     sync.Mutex
	in     io.Reader
	out    io.Writer
	closer io.Closer
	reader *bufio.Reader
	// pending is non-nil only when a terminal read outlived the Request that
	// started it (normally because that approval timed out/cancelled). A result
	// from such a read belongs to the old call and must be discarded before a
	// new call can be prompted. Reusing it would let a late "yes" for call A
	// authorize call B.
	pending chan readResult
}

type readResult struct {
	approved bool
	err      error
}

func NewTTYApprover() (*TTYApprover, error) {
	if a, err := NewTTYApproverStrict(); err == nil {
		return a, nil
	}
	return &TTYApprover{in: os.Stdin, out: os.Stderr}, nil
}

func NewTTYApproverStrict() (*TTYApprover, error) {
	f, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("approval: open /dev/tty: %w", err)
	}
	return &TTYApprover{in: f, out: f, closer: f}, nil
}

func NewTTYApproverWithIO(in io.Reader, out io.Writer) *TTYApprover {
	return &TTYApprover{in: in, out: out}
}

func (a *TTYApprover) Close() error {
	if a.closer != nil {
		return a.closer.Close()
	}
	return nil
}

// discardStalePending prevents a terminal response from a timed-out/cancelled
// approval from being applied to a later tool call. The old blocking read
// cannot be safely cancelled on every supported terminal, so the next Request
// waits for that read to finish and discards its result before displaying a new
// approval prompt. The caller's context bounds this fail-closed drain.
func (a *TTYApprover) discardStalePending(ctx context.Context, call policy.ToolCall) error {
	if a.pending == nil {
		return nil
	}

	if _, err := fmt.Fprintf(a.out,
		"AgentFence: discarding a late response from a previous timed-out approval before prompting for [%s] %s; press Enter if needed\n",
		call.ID, call.Tool); err != nil {
		return fmt.Errorf("approval: write stale-response notice: %w", err)
	}

	select {
	case <-a.pending:
		a.pending = nil
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (a *TTYApprover) Request(ctx context.Context, call policy.ToolCall) (bool, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if err := ctx.Err(); err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			fmt.Fprintf(a.out, "AgentFence: approval timeout for [%s] %s — denying\n", call.ID, call.Tool)
		}
		return false, err
	}

	// A response still pending from an earlier timed-out/cancelled request is
	// stale by definition. Drain and discard it *before* showing the next
	// prompt; never reinterpret the old keystroke as approval for this call.
	if err := a.discardStalePending(ctx, call); err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			fmt.Fprintf(a.out, "AgentFence: approval timeout for [%s] %s while clearing stale input — denying\n", call.ID, call.Tool)
		}
		return false, err
	}

	if _, err := fmt.Fprintf(a.out, "AgentFence: approve %s [%s]? (y/N): ", call.Tool, call.ID); err != nil {
		return false, fmt.Errorf("approval: write prompt: %w", err)
	}

	if a.reader == nil {
		a.reader = bufio.NewReader(a.in)
	}
	reader := a.reader
	ch := make(chan readResult, 1)
	go func() {
		line, err := reader.ReadString('\n')
		if err != nil && !errors.Is(err, io.EOF) {
			ch <- readResult{false, err}
			return
		}
		ch <- readResult{isYes(line), nil}
	}()

	select {
	case r := <-ch:
		if r.err != nil {
			return false, fmt.Errorf("approval: read response: %w", r.err)
		}
		return r.approved, nil
	case <-ctx.Done():
		// The read goroutine may still be blocked on the terminal. Retain its
		// channel solely so the next Request can drain/discard the old response.
		// It must never be used as the next call's approval result.
		a.pending = ch
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			fmt.Fprintf(a.out, "\nAgentFence: approval timeout for [%s] %s — denying\n", call.ID, call.Tool)
		}
		return false, ctx.Err()
	}
}

func isYes(line string) bool {
	trimmed := strings.ToLower(strings.TrimSpace(line))
	return trimmed == "y" || trimmed == "yes"
}
