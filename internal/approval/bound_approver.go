package approval

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/dgenio/agentfence/internal/policy"
)

// BoundApprover decides whether an immutable exact action/policy request may
// proceed. Implementations must fail closed when the request cannot be
// validated or displayed safely.
type BoundApprover interface {
	RequestBound(ctx context.Context, request BoundRequest) (bool, error)
}

// RequestBound keeps the non-interactive fallback fail-closed.
func (DenyAllApprover) RequestBound(_ context.Context, request BoundRequest) (bool, error) {
	if err := request.Validate(); err != nil {
		return false, err
	}
	return false, nil
}

// ResolveBound is the bound-request counterpart to Resolve. It preserves the
// same timeout/cancellation/I/O outcome taxonomy while ensuring the approver
// only sees an exact validated request.
func ResolveBound(ctx context.Context, approver BoundApprover, request BoundRequest, timeout time.Duration, noInteractive bool) (Outcome, error) {
	if err := request.Validate(); err != nil {
		return Outcome{Reason: ReasonApprovalIOError, Code: policy.ReasonCodeApprovalIOError}, err
	}
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}

	approved, err := approver.RequestBound(ctx, request)
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

// RequestBound preserves TTYApprover's serialized prompt/read state machine,
// including stale-response draining, but renders only the safe BoundRequest
// prompt. A late response from a timed-out request can never authorize the next
// bound request.
func (a *TTYApprover) RequestBound(ctx context.Context, request BoundRequest) (bool, error) {
	if err := request.Validate(); err != nil {
		return false, err
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	if err := ctx.Err(); err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			_, _ = fmt.Fprintln(a.out, "AgentFence: bound approval timeout — denying")
		}
		return false, err
	}

	if err := a.discardStalePendingBound(ctx); err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			_, _ = fmt.Fprintln(a.out, "AgentFence: bound approval timeout while clearing stale input — denying")
		}
		return false, err
	}

	if _, err := io.WriteString(a.out, request.Prompt()); err != nil {
		return false, fmt.Errorf("approval: write bound prompt: %w", err)
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
	case result := <-ch:
		if result.err != nil {
			return false, fmt.Errorf("approval: read bound response: %w", result.err)
		}
		return result.approved, nil
	case <-ctx.Done():
		a.pending = ch
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			_, _ = fmt.Fprintln(a.out, "\nAgentFence: bound approval timeout — denying")
		}
		return false, ctx.Err()
	}
}

func (a *TTYApprover) discardStalePendingBound(ctx context.Context) error {
	if a.pending == nil {
		return nil
	}
	if _, err := fmt.Fprintln(a.out, "AgentFence: discarding a late response from a previous timed-out approval before the next bound prompt; press Enter if needed"); err != nil {
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
