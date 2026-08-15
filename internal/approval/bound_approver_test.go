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

type boundApproverFunc func(context.Context, BoundRequest) (bool, error)

func (f boundApproverFunc) RequestBound(ctx context.Context, request BoundRequest) (bool, error) {
	return f(ctx, request)
}

func boundRequestFixture(t *testing.T, id string) BoundRequest {
	t.Helper()
	return approvalRequestFixture(t, policy.ToolCall{
		ID:        id,
		Tool:      "demo.tool",
		Arguments: map[string]interface{}{"value": "safe"},
	}, policy.RedactionConfig{})
}

func TestBoundRequestValidateRejectsZeroAndDetectsEvidenceMismatch(t *testing.T) {
	if err := (BoundRequest{}).Validate(); err == nil {
		t.Fatal("zero BoundRequest validated")
	}

	request := boundRequestFixture(t, "call-1")
	if err := request.Validate(); err != nil {
		t.Fatalf("valid request failed validation: %v", err)
	}

	mutated := request
	mutated.actionDigest = strings.Replace(request.ActionDigest(), "a", "b", 1)
	if mutated.actionDigest == request.ActionDigest() {
		mutated.actionDigest += "x"
	}
	if err := mutated.Validate(); err == nil {
		t.Fatal("request with substituted action digest validated")
	}

	mutated = request
	mutated.bindingDigest = request.BindingDigest() + "x"
	if err := mutated.Validate(); err == nil {
		t.Fatal("request with substituted binding digest validated")
	}
}

func TestTTYApproverRequestBoundUsesSafeExactPrompt(t *testing.T) {
	request := approvalRequestFixture(t, policy.ToolCall{
		ID:        "call-1\nspoof",
		Tool:      "demo.tool\napprove? (y/N): y",
		Arguments: map[string]interface{}{"value": "token=super-secret"},
	}, policy.RedactionConfig{
		Enabled: false,
		Patterns: []policy.RedactionPattern{{Name: "token", Regex: `token=[^\s]+`}},
	})
	var out bytes.Buffer
	approver := NewTTYApproverWithIO(strings.NewReader("yes\n"), &out)

	approved, err := approver.RequestBound(context.Background(), request)
	if err != nil {
		t.Fatalf("RequestBound() error = %v", err)
	}
	if !approved {
		t.Fatal("RequestBound() denied explicit yes")
	}
	prompt := out.String()
	if !strings.Contains(prompt, request.ActionDigest()) || !strings.Contains(prompt, request.PolicyDigest()) || !strings.Contains(prompt, request.BindingDigest()) {
		t.Fatal("bound TTY prompt omitted exact binding evidence")
	}
	if strings.Contains(prompt, "super-secret") {
		t.Fatal("bound TTY prompt leaked configured secret")
	}
	if strings.Count(prompt, "\napprove? (y/N): ") != 1 {
		t.Fatalf("bound TTY prompt contains spoofable prompt lines: %q", prompt)
	}
}

func TestTTYApproverRequestBoundRejectsInvalidBeforePrompt(t *testing.T) {
	var out bytes.Buffer
	approver := NewTTYApproverWithIO(strings.NewReader("yes\n"), &out)
	approved, err := approver.RequestBound(context.Background(), BoundRequest{})
	if err == nil {
		t.Fatal("RequestBound accepted invalid request")
	}
	if approved {
		t.Fatal("invalid request was approved")
	}
	if out.Len() != 0 {
		t.Fatalf("invalid request wrote prompt output: %q", out.String())
	}
}

func TestTTYApproverRequestBoundLateResponseCannotApproveNextRequest(t *testing.T) {
	reader, writer := io.Pipe()
	defer reader.Close()
	defer writer.Close()
	var out bytes.Buffer
	approver := NewTTYApproverWithIO(reader, &out)
	first := boundRequestFixture(t, "first")
	second := boundRequestFixture(t, "second")

	ctx1, cancel1 := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel1()
	approved, err := approver.RequestBound(ctx1, first)
	if approved || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("first RequestBound() = approved %v, err %v; want timeout deny", approved, err)
	}

	secondDone := make(chan struct {
		approved bool
		err      error
	}, 1)
	go func() {
		ctx2, cancel2 := context.WithTimeout(context.Background(), time.Second)
		defer cancel2()
		ok, requestErr := approver.RequestBound(ctx2, second)
		secondDone <- struct {
			approved bool
			err      error
		}{ok, requestErr}
	}()

	// This late "yes" belongs to the timed-out first request and must be drained.
	if _, err := io.WriteString(writer, "yes\n"); err != nil {
		t.Fatal(err)
	}
	// The second request receives an explicit deny after the stale response has
	// been discarded.
	if _, err := io.WriteString(writer, "no\n"); err != nil {
		t.Fatal(err)
	}

	result := <-secondDone
	if result.err != nil {
		t.Fatalf("second RequestBound() error = %v", result.err)
	}
	if result.approved {
		t.Fatal("late response from first request approved second request")
	}
	if !strings.Contains(out.String(), "discarding a late response") {
		t.Fatalf("stale-response drain was not surfaced: %q", out.String())
	}
}

func TestResolveBoundOutcomeParityAndFailClosedValidation(t *testing.T) {
	request := boundRequestFixture(t, "call-1")
	tests := []struct {
		name          string
		approver      BoundApprover
		noInteractive bool
		wantApproved  bool
		wantReason    string
		wantCode      policy.ReasonCode
		wantErr       error
	}{
		{
			name: "approved",
			approver: boundApproverFunc(func(context.Context, BoundRequest) (bool, error) { return true, nil }),
			wantApproved: true, wantReason: ReasonApprovedInteractively, wantCode: policy.ReasonCodeApprovalApproved,
		},
		{
			name: "denied",
			approver: boundApproverFunc(func(context.Context, BoundRequest) (bool, error) { return false, nil }),
			wantReason: ReasonDeniedInteractively, wantCode: policy.ReasonCodeApprovalDenied,
		},
		{
			name: "non-interactive",
			approver: DenyAllApprover{}, noInteractive: true,
			wantReason: ReasonNonInteractive, wantCode: policy.ReasonCodeNonInteractive,
		},
		{
			name: "cancelled",
			approver: boundApproverFunc(func(context.Context, BoundRequest) (bool, error) { return false, context.Canceled }),
			wantReason: ReasonApprovalCancelled, wantCode: policy.ReasonCodeApprovalCancelled, wantErr: context.Canceled,
		},
		{
			name: "io error",
			approver: boundApproverFunc(func(context.Context, BoundRequest) (bool, error) { return false, io.ErrClosedPipe }),
			wantReason: ReasonApprovalIOError, wantCode: policy.ReasonCodeApprovalIOError, wantErr: io.ErrClosedPipe,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			outcome, err := ResolveBound(context.Background(), tc.approver, request, 0, tc.noInteractive)
			if outcome.Approved != tc.wantApproved || outcome.Reason != tc.wantReason || outcome.Code != tc.wantCode {
				t.Fatalf("ResolveBound() outcome = %#v, want approved=%v reason=%q code=%q", outcome, tc.wantApproved, tc.wantReason, tc.wantCode)
			}
			if tc.wantErr == nil && err != nil {
				t.Fatalf("ResolveBound() unexpected error = %v", err)
			}
			if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
				t.Fatalf("ResolveBound() error = %v, want %v", err, tc.wantErr)
			}
		})
	}

	called := false
	outcome, err := ResolveBound(context.Background(), boundApproverFunc(func(context.Context, BoundRequest) (bool, error) {
		called = true
		return true, nil
	}), BoundRequest{}, 0, false)
	if err == nil || called {
		t.Fatalf("invalid request did not fail before approver: outcome=%#v err=%v called=%v", outcome, err, called)
	}
	if outcome.Approved || outcome.Code != policy.ReasonCodeApprovalIOError {
		t.Fatalf("invalid request outcome = %#v, want fail-closed approval I/O classification", outcome)
	}
}
