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

// ReasonApprovedInteractively is the audit reason recorded when the operator
// approves an ask decision interactively.
const ReasonApprovedInteractively = "approved interactively"

// ReasonDeniedInteractively is the audit reason recorded when the operator
// rejects an ask decision interactively (explicit n, empty enter, EOF).
const ReasonDeniedInteractively = "denied interactively"

// ReasonApprovalTimeout is the audit reason recorded when an approval prompt
// times out and the call is auto-denied.
const ReasonApprovalTimeout = "approval timeout"

// ReasonApprovalCancelled is the audit reason recorded when the approval
// context is cancelled (e.g., parent shutdown) and the call is auto-denied.
const ReasonApprovalCancelled = "approval cancelled"

// ReasonApprovalIOError is the audit reason recorded when the approver
// encounters an I/O failure (TTY gone, broken pipe) and the call is
// auto-denied. The error detail is surfaced to stderr.
const ReasonApprovalIOError = "approval I/O error"

// ReasonNonInteractive is the audit reason recorded when the operator disabled
// interactive approval (--no-interactive) and an ask decision was auto-denied.
const ReasonNonInteractive = "non-interactive: ask auto-denied"

// Approver decides whether to allow a tool call that policy evaluated as ask.
//
// Returning true means the call may proceed (effectively converting ask to
// allow). Returning false means the call must be blocked (ask becomes deny).
//
// The returned error is non-nil only for I/O errors; a context deadline or
// cancellation must be reported as (false, context.DeadlineExceeded) (or
// context.Canceled) and treated as deny by callers.
type Approver interface {
	Request(ctx context.Context, call policy.ToolCall) (bool, error)
}

// DenyAllApprover unconditionally denies. It is the default for
// --no-interactive contexts and is also the safest fallback when no TTY is
// available.
type DenyAllApprover struct{}

// Request always returns (false, nil).
func (DenyAllApprover) Request(_ context.Context, _ policy.ToolCall) (bool, error) {
	return false, nil
}

// Outcome is the resolved result of an ask approval: whether the call may
// proceed and the canonical audit reason describing why.
type Outcome struct {
	// Approved reports whether the ask decision was converted to allow.
	Approved bool
	// Reason is the canonical audit reason for the outcome — one of the
	// Reason* constants in this package.
	Reason string
}

// Resolve runs approver for an ask decision and maps the result to a final
// allow/deny Outcome with the canonical audit reason, applying an optional
// timeout. It is the single place that decision-to-reason mapping lives, so
// the check command and both proxies report ask outcomes identically.
//
// When timeout > 0 the request is bounded by a context deadline; on expiry the
// call is denied with ReasonApprovalTimeout. A denial with no I/O error is
// reported as ReasonNonInteractive when noInteractive is set, otherwise
// ReasonDeniedInteractively.
//
// The returned error is the approver's raw error (a context error on
// timeout/cancel, or an I/O failure), exposed so callers can log the detail;
// the audit-facing reason is already captured in Outcome.Reason. Callers must
// treat any non-Approved Outcome as deny regardless of the error (fail closed).
func Resolve(ctx context.Context, approver Approver, call policy.ToolCall, timeout time.Duration, noInteractive bool) (Outcome, error) {
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}

	approved, err := approver.Request(ctx, call)
	switch {
	case approved:
		return Outcome{Approved: true, Reason: ReasonApprovedInteractively}, err
	case errors.Is(err, context.DeadlineExceeded):
		return Outcome{Reason: ReasonApprovalTimeout}, err
	case errors.Is(err, context.Canceled):
		return Outcome{Reason: ReasonApprovalCancelled}, err
	case err != nil:
		return Outcome{Reason: ReasonApprovalIOError}, err
	case noInteractive:
		return Outcome{Reason: ReasonNonInteractive}, nil
	default:
		return Outcome{Reason: ReasonDeniedInteractively}, nil
	}
}

// TTYApprover prompts the operator on a real terminal for each ask decision.
//
// Construct it with NewTTYApprover for production use (opens /dev/tty and
// falls back to os.Stdin/os.Stderr); use NewTTYApproverWithIO in tests to
// inject fake reader/writer pairs.
type TTYApprover struct {
	mu     sync.Mutex
	in     io.Reader
	out    io.Writer
	closer io.Closer
	// reader is created once and reused across calls so bytes buffered by one
	// prompt are not discarded when the next prompt begins.
	reader *bufio.Reader
	// pending holds an in-flight read goroutine's result. When a Request times
	// out, its read goroutine stays parked on the terminal; the next Request
	// adopts this channel instead of spawning a second reader on the same fd,
	// so a late keystroke is delivered to one prompt rather than raced for.
	pending chan readResult
}

// readResult carries the outcome of a single blocking terminal read.
type readResult struct {
	approved bool
	err      error
}

// NewTTYApprover opens /dev/tty for read/write so the prompt and response do
// not collide with stdin (which may carry tool-call JSONL) or stdout (which
// may carry structured output). On platforms where /dev/tty is unavailable
// (Windows, some CI environments) it falls back to os.Stdin for input and
// os.Stderr for the prompt.
//
// The returned approver owns any opened file handle; call Close when done.
func NewTTYApprover() (*TTYApprover, error) {
	if a, err := NewTTYApproverStrict(); err == nil {
		return a, nil
	}
	// Fallback: prompt to stderr, read from stdin. This is good enough for
	// `check` where stdin is the user's terminal (the call file is read via
	// --call, not stdin). It is NOT safe for the stdio proxy, whose stdin
	// carries the agent's JSON-RPC channel — proxies must use
	// NewTTYApproverStrict so a missing terminal fails loudly instead.
	return &TTYApprover{in: os.Stdin, out: os.Stderr}, nil
}

// NewTTYApproverStrict opens /dev/tty and returns an error if it is
// unavailable, never falling back to os.Stdin. Long-running proxies must use
// this: the stdio proxy's stdin is the agent's JSON-RPC channel, so reading
// approvals from stdin would block on protocol traffic and corrupt the stream.
// Callers should tell operators to pass --no-interactive when no controlling
// terminal is present.
func NewTTYApproverStrict() (*TTYApprover, error) {
	f, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("approval: open /dev/tty: %w", err)
	}
	return &TTYApprover{in: f, out: f, closer: f}, nil
}

// NewTTYApproverWithIO returns an approver that reads from in and writes to
// out. Intended for tests; production callers should use NewTTYApprover.
func NewTTYApproverWithIO(in io.Reader, out io.Writer) *TTYApprover {
	return &TTYApprover{in: in, out: out}
}

// Close releases any underlying file handle opened by NewTTYApprover. Safe to
// call on approvers constructed via NewTTYApproverWithIO (no-op).
func (a *TTYApprover) Close() error {
	if a.closer != nil {
		return a.closer.Close()
	}
	return nil
}

// Request prompts the operator and waits for a y/n response, the context to
// expire, or input to close.
//
// Approval requires an explicit "y" or "yes" (case-insensitive); any other
// input — including empty Enter, "n", "no", EOF, or unrecognised text —
// denies. Context cancellation or deadline expiry auto-denies.
func (a *TTYApprover) Request(ctx context.Context, call policy.ToolCall) (bool, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	// Short-circuit if the context is already done — avoids spawning a
	// goroutine that would immediately race against ctx.Done().
	if err := ctx.Err(); err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			fmt.Fprintf(a.out, "AgentFence: approval timeout for [%s] %s — denying\n", call.ID, call.Tool)
		}
		return false, err
	}

	if _, err := fmt.Fprintf(a.out, "AgentFence: approve %s [%s]? (y/N): ", call.Tool, call.ID); err != nil {
		return false, fmt.Errorf("approval: write prompt: %w", err)
	}

	// Reuse a single reader and a single in-flight read across calls. If a prior
	// Request timed out, its read goroutine is still parked on the terminal;
	// adopt its pending channel rather than spawning a second reader on the same
	// fd (two readers would race for the operator's keystroke, and a discarded
	// bufio.Reader could drop already-buffered bytes).
	if a.pending == nil {
		if a.reader == nil {
			a.reader = bufio.NewReader(a.in)
		}
		reader := a.reader
		ch := make(chan readResult, 1)
		go func() {
			line, err := reader.ReadString('\n')
			// EOF with no input means "no response" → deny, not an error.
			if err != nil && !errors.Is(err, io.EOF) {
				ch <- readResult{false, err}
				return
			}
			ch <- readResult{isYes(line), nil}
		}()
		a.pending = ch
	}

	select {
	case r := <-a.pending:
		a.pending = nil
		if r.err != nil {
			return false, fmt.Errorf("approval: read response: %w", r.err)
		}
		return r.approved, nil
	case <-ctx.Done():
		// Leave a.pending in place: the read goroutine is still blocked on the
		// terminal, so the next Request consumes its result. This keeps exactly
		// one reader on the fd and never loses or steals a late keystroke.
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			fmt.Fprintf(a.out, "\nAgentFence: approval timeout for [%s] %s — denying\n", call.ID, call.Tool)
		}
		return false, ctx.Err()
	}
}

// isYes reports whether line (with any surrounding whitespace and newline)
// is an affirmative response. Default is no.
func isYes(line string) bool {
	trimmed := strings.ToLower(strings.TrimSpace(line))
	return trimmed == "y" || trimmed == "yes"
}
