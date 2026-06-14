// Package proxy implements the AgentFence MCP stdio proxy.
//
// The proxy spawns an MCP server as a subprocess and relays newline-delimited
// JSON-RPC messages in both directions. Unless the proxy is configured for
// passthrough mode, every tools/call request from the agent is parsed and
// evaluated against the policy engine before being forwarded:
//
//   - allow → the original message is forwarded unchanged.
//   - deny  → a JSON-RPC error response (ErrorCodeBlockedByPolicy) is sent
//     back to the agent; the subprocess never sees the request.
//   - ask   → the Approver decides at runtime; an approved call is
//     forwarded, a denied one becomes the same error response as
//     a direct deny.
//
// Non-tools/call messages (notifications, initialize, ping, etc.) are
// forwarded untouched. Lines that fail to parse as JSON-RPC are also
// forwarded untouched, leaving downstream parsing failures visible at the
// agent or MCP server rather than being silently swallowed by the proxy.
package proxy

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sync"
	"sync/atomic"
	"time"

	"github.com/dgenio/agentfence/internal/approval"
	"github.com/dgenio/agentfence/internal/audit"
	"github.com/dgenio/agentfence/internal/engine"
	"github.com/dgenio/agentfence/internal/mcp"
	"github.com/dgenio/agentfence/internal/policy"
)

// maxScanLine is the per-line buffer cap for JSON-RPC frames over stdio.
// MCP messages can include base64-encoded blobs and large structured results,
// so the default bufio.Scanner limit (64 KiB) is too tight.
const maxScanLine = 16 * 1024 * 1024 // 16 MiB

// Approver decides whether an "ask" decision becomes an allow or deny at
// runtime. It is an alias for approval.Approver: the stdio proxy, the HTTP
// proxy, and the check command all share one contract so a single approver
// implementation (e.g. approval.TTYApprover) wires into every call site
// without adapters.
type Approver = approval.Approver

// DenyAllApprover converts every ask decision into deny. It is an alias for
// approval.DenyAllApprover — the shared fail-closed default used in
// non-interactive contexts (CI, --no-interactive) and whenever no TTY is
// available, so the intercept loop never silently treats ask as allow.
type DenyAllApprover = approval.DenyAllApprover

// Options configures Run. Engine and AuditWriter are required when
// Passthrough is false; the rest have sensible defaults documented below.
type Options struct {
	// Engine evaluates each intercepted tools/call. Required unless
	// Passthrough is true.
	Engine *engine.Engine

	// AuditWriter records evaluation decisions. Required unless Passthrough
	// is true (passthrough never invokes the engine, so there is nothing to
	// audit). Pass audit.NewWriter(io.Discard) to keep audit calls cheap if
	// you need an enforcement-mode proxy without on-disk audit. Audit records
	// are written before the forwarding decision is acted on so the audit
	// trail reflects every decision the engine made.
	AuditWriter *audit.Writer

	// Approver handles ask decisions. Defaults to DenyAllApprover.
	Approver Approver

	// ApprovalTimeout bounds how long a single ask prompt may wait before the
	// call is auto-denied with the approval-timeout reason. Zero waits
	// indefinitely (subject to ctx cancellation).
	ApprovalTimeout time.Duration

	// NoInteractive records that interactive approval was disabled, so a
	// denied ask is attributed to the non-interactive reason rather than an
	// explicit operator rejection. It does not by itself select the approver;
	// callers pass DenyAllApprover when this is set.
	NoInteractive bool

	// Passthrough forwards every message in both directions without
	// touching it. Use this only to validate the relay; production
	// deployments should leave it false.
	Passthrough bool

	// Debug logs every forwarded line to Logger. Disabled by default
	// because MCP messages routinely contain user content.
	Debug bool

	// Stdin, Stdout, Stderr default to the process's os.Stdin/Stdout/Stderr
	// when nil. Tests override these to drive the relay deterministically.
	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer

	// Logger receives proxy-internal diagnostics (errors, debug lines).
	// Defaults to io.Discard so the proxy stays silent unless Debug is on.
	Logger io.Writer
}

// Run spawns command + args as a subprocess and relays JSON-RPC messages
// between the agent (Options.Stdin/Stdout) and the subprocess.
//
// Run blocks until both relay directions close. It then waits for the
// subprocess to exit and returns the subprocess's error (or nil on a clean
// exit). When the subprocess exits with a non-zero status, the returned
// error is an *exec.ExitError; callers can extract the code with errors.As.
//
// Cancelling ctx terminates the subprocess via exec.CommandContext.
func Run(ctx context.Context, command string, args []string, opts Options) error {
	if command == "" {
		return errors.New("proxy: command is required")
	}
	if !opts.Passthrough {
		if opts.Engine == nil {
			return errors.New("proxy: Engine is required when not in passthrough mode")
		}
		if opts.AuditWriter == nil {
			return errors.New("proxy: AuditWriter is required when not in passthrough mode (use audit.NewWriter(io.Discard) to disable)")
		}
	}
	opts = applyDefaults(opts)

	cmd := exec.CommandContext(ctx, command, args...)
	subIn, err := cmd.StdinPipe()
	if err != nil {
		return fmt.Errorf("proxy: stdin pipe: %w", err)
	}
	subOut, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("proxy: stdout pipe: %w", err)
	}
	cmd.Stderr = opts.Stderr

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("proxy: start %s: %w", command, err)
	}

	var sess *engine.Session
	if !opts.Passthrough {
		sess = opts.Engine.NewSession()
	}
	r := newRelay(opts, sess)
	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		defer subIn.Close() // EOF the subprocess when the agent closes its end.
		r.relayAgentToSub(ctx, opts.Stdin, subIn, opts.Stdout)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		r.relaySubToAgent(subOut, opts.Stdout)
	}()

	wg.Wait()
	return cmd.Wait()
}

func applyDefaults(opts Options) Options {
	if opts.Stdin == nil {
		opts.Stdin = os.Stdin
	}
	if opts.Stdout == nil {
		opts.Stdout = os.Stdout
	}
	if opts.Stderr == nil {
		opts.Stderr = os.Stderr
	}
	if opts.Logger == nil {
		opts.Logger = io.Discard
	}
	if opts.Approver == nil {
		opts.Approver = DenyAllApprover{}
	}
	// Wrap the agent's stdout in a mutex-protected writer so that the
	// synthesized-response goroutine (agent->subproc relay, writing deny
	// and ask-deny responses) cannot interleave a JSON-RPC frame with the
	// subproc->agent goroutine forwarding a real result. POSIX only
	// guarantees write atomicity below PIPE_BUF (typically 4 KiB); MCP
	// tool results routinely exceed that.
	if _, alreadyLocked := opts.Stdout.(*lockedWriter); !alreadyLocked {
		opts.Stdout = &lockedWriter{w: opts.Stdout}
	}
	return opts
}

// lockedWriter serialises Write calls onto an underlying writer. Used to
// keep JSON-RPC frames atomic on the agent's stdout when two relay
// goroutines write to it concurrently.
type lockedWriter struct {
	mu sync.Mutex
	w  io.Writer
}

// Write delegates to the underlying writer while holding the mutex.
func (lw *lockedWriter) Write(p []byte) (int, error) {
	lw.mu.Lock()
	defer lw.mu.Unlock()
	return lw.w.Write(p)
}

// relay holds per-Run mutable state (the call counter, the evaluation session,
// and — when taint tracking is on — the in-flight request→tool map used to
// attribute a tool result back to the call that produced it). It is
// intentionally not exported: callers should drive the proxy via Run.
type relay struct {
	opts        Options
	sess        *engine.Session
	callCounter uint64

	// pending maps a forwarded tools/call request ID (normalised JSON bytes)
	// to the tool name, so a later response with the same ID can attribute the
	// result to its tool for taint observation. Only used when taint is on.
	pendingMu sync.Mutex
	pending   map[string]string
}

func newRelay(opts Options, sess *engine.Session) *relay {
	r := &relay{opts: opts, sess: sess}
	if sess != nil && sess.TaintEnabled() {
		r.pending = map[string]string{}
	}
	return r
}

// taintEnabled reports whether this relay should track tool-output taint.
func (r *relay) taintEnabled() bool {
	return r.pending != nil
}

// rememberPending records that a forwarded tools/call with the given request ID
// is for tool. A no-op when taint tracking is off or the request is a
// notification (no ID to correlate a response against).
func (r *relay) rememberPending(id json.RawMessage, tool string) {
	if !r.taintEnabled() || isNotificationID(id) {
		return
	}
	r.pendingMu.Lock()
	r.pending[normalizeID(id)] = tool
	r.pendingMu.Unlock()
}

// takePending returns and clears the tool name recorded for a response ID.
func (r *relay) takePending(id json.RawMessage) (string, bool) {
	if !r.taintEnabled() || isNotificationID(id) {
		return "", false
	}
	r.pendingMu.Lock()
	defer r.pendingMu.Unlock()
	key := normalizeID(id)
	tool, ok := r.pending[key]
	if ok {
		delete(r.pending, key)
	}
	return tool, ok
}

func normalizeID(id json.RawMessage) string {
	return string(bytes.TrimSpace(id))
}

func (r *relay) relayAgentToSub(ctx context.Context, in io.Reader, subStdin, agentStdout io.Writer) {
	scanner := bufio.NewScanner(in)
	scanner.Buffer(make([]byte, 64*1024), maxScanLine)
	for scanner.Scan() {
		line := append([]byte(nil), scanner.Bytes()...) // copy: scanner reuses its buffer
		if err := r.processAgentLine(ctx, line, subStdin, agentStdout); err != nil {
			fmt.Fprintln(r.opts.Logger, "proxy: agent->subproc:", err)
			return
		}
	}
	if err := scanner.Err(); err != nil {
		fmt.Fprintln(r.opts.Logger, "proxy: scan agent stdin:", err)
	}
}

func (r *relay) relaySubToAgent(subStdout io.Reader, agentStdout io.Writer) {
	scanner := bufio.NewScanner(subStdout)
	scanner.Buffer(make([]byte, 64*1024), maxScanLine)
	for scanner.Scan() {
		line := scanner.Bytes()
		if r.opts.Debug {
			fmt.Fprintf(r.opts.Logger, "proxy: subproc->agent: %s\n", line)
		}
		// Before forwarding, attribute tool results to their originating tool
		// and feed them to the taint tracker. This is the confused-deputy
		// observation point: untrusted output seen here can taint a later call.
		if r.taintEnabled() {
			r.observeResult(line)
		}
		if _, err := writeLine(agentStdout, line); err != nil {
			fmt.Fprintln(r.opts.Logger, "proxy: subproc->agent:", err)
			return
		}
	}
	if err := scanner.Err(); err != nil {
		fmt.Fprintln(r.opts.Logger, "proxy: scan subproc stdout:", err)
	}
}

// processAgentLine handles one line from the agent. It writes either to
// subStdin (forwarded request) or agentStdout (synthesized error response).
//
// The function is the package's testable seam: tests construct a relay with
// in-memory writers and drive it line by line without needing a subprocess.
func (r *relay) processAgentLine(ctx context.Context, line []byte, subStdin, agentStdout io.Writer) error {
	if r.opts.Debug {
		fmt.Fprintf(r.opts.Logger, "proxy: agent->subproc: %s\n", line)
	}

	// Passthrough mode: forward everything, no parsing.
	if r.opts.Passthrough {
		_, err := writeLine(subStdin, line)
		return err
	}

	// Non-JSON-RPC or non-tools/call lines are forwarded untouched. This
	// keeps the proxy transparent for initialize, ping, notifications,
	// and any future MCP method AgentFence does not gate.
	req, err := mcp.ParseRequest(line)
	if err != nil || req.Method != mcp.MethodToolsCall {
		_, err := writeLine(subStdin, line)
		return err
	}

	// Notifications are JSON-RPC requests without an id (or with id=null).
	// The spec forbids sending a response to them, so on deny / ask-deny /
	// invalid-params we must drop the line instead of synthesising a
	// response with "id":null that some clients reject.
	isNotification := isNotificationID(req.ID)

	params, perr := mcp.ParseToolCallParams(req.Params)
	if perr != nil {
		// Malformed tools/call: answer the agent with a well-formed error
		// (for regular requests) or drop the line (for notifications).
		// No audit event in either case because the engine never saw a
		// valid call.
		if isNotification {
			fmt.Fprintln(r.opts.Logger,
				"proxy: dropping malformed tools/call notification:", perr)
			return nil
		}
		return writeResponse(agentStdout, mcp.InvalidParamsError(req.ID, perr.Error()))
	}

	fallback := fmt.Sprintf("call-%d", atomic.AddUint64(&r.callCounter, 1))
	callID := mcp.CallIDFromRequestID(req.ID, fallback)
	call := params.ToToolCall(callID)
	result, event := r.sess.Evaluate(call)

	// Resolve an ask decision to a final allow/deny via the approver before we
	// audit, so the audit event records the outcome the agent actually saw
	// (mirrors the check command's resolveAsk). The approver runs first; the
	// engine event is then rewritten to the resolved decision and reason.
	if result.Decision == policy.DecisionAsk {
		outcome, aerr := approval.Resolve(ctx, r.opts.Approver, call, r.opts.ApprovalTimeout, r.opts.NoInteractive)
		if outcome.Approved {
			result.Decision = policy.DecisionAllow
		} else {
			result.Decision = policy.DecisionDeny
		}
		// Preserve the engine's reason for *why* the call was ask (e.g. a taint
		// escalation) and annotate it with the approval outcome, so the audit
		// trail keeps both the cause and how it was resolved.
		if result.Reason == "" {
			result.Reason = outcome.Reason
		} else {
			result.Reason = result.Reason + " (" + outcome.Reason + ")"
		}
		event.Decision = result.Decision
		event.Reason = result.Reason
		if outcome.Reason == approval.ReasonApprovalIOError {
			// Surface the I/O detail to the operator only; the agent sees the
			// canonical reason, not the internal error text.
			fmt.Fprintf(r.opts.Logger, "proxy: approval I/O error for [%s] %s: %v\n", call.ID, call.Tool, aerr)
		}
	}

	// Audit so the decision is durable even if the forwarding step fails
	// (e.g. subprocess pipe closed mid-relay).
	if writeErr := r.opts.AuditWriter.Write(event); writeErr != nil {
		fmt.Fprintln(r.opts.Logger, "proxy: audit write:", writeErr)
	}

	switch result.Decision {
	case policy.DecisionAllow:
		r.rememberPending(req.ID, call.Tool)
		_, err := writeLine(subStdin, line)
		return err
	case policy.DecisionDeny:
		if isNotification {
			return nil
		}
		return writeResponse(agentStdout, mcp.BlockedByPolicyError(req.ID, result.Reason))
	default:
		// Unknown decision (engine extension): default-deny so a future
		// decision value cannot silently widen the allow set.
		if isNotification {
			return nil
		}
		return writeResponse(agentStdout,
			mcp.BlockedByPolicyError(req.ID,
				"unknown decision: "+string(result.Decision)))
	}
}

// observeResult parses a subprocess→agent line as a JSON-RPC response and, when
// it answers a tools/call this relay forwarded, feeds the result's text content
// to the taint tracker attributed to the originating tool. Lines that are not
// responses, carry no result, or have no matching pending request are ignored.
func (r *relay) observeResult(line []byte) {
	resp, err := mcp.ParseResponse(line)
	if err != nil || len(resp.Result) == 0 {
		return
	}
	tool, ok := r.takePending(resp.ID)
	if !ok {
		return
	}
	text := mcp.ResultText(resp.Result)
	if text == "" {
		return
	}
	r.sess.ObserveResult(tool, text)
}

// isNotificationID reports whether a JSON-RPC request ID indicates a
// notification (absent or null). Per JSON-RPC 2.0 §4.1 a notification is a
// request without an id member, and the server MUST NOT reply to one. We
// also treat explicit null IDs the same way: there is no useful response
// id to echo, and some clients treat "id":null as a notification.
func isNotificationID(id json.RawMessage) bool {
	trimmed := bytes.TrimSpace(id)
	return len(trimmed) == 0 || string(trimmed) == "null"
}

func writeLine(w io.Writer, line []byte) (int, error) {
	// Build a single contiguous slice and let the writer (a lockedWriter
	// when Stdout is shared by both relay goroutines — see applyDefaults)
	// keep the JSON-RPC frame atomic. POSIX only guarantees write atomicity
	// below PIPE_BUF, so two non-locked Write calls — or even one large
	// Write — could be interleaved by the kernel without the lock.
	buf := make([]byte, len(line)+1)
	copy(buf, line)
	buf[len(line)] = '\n'
	return w.Write(buf)
}

func writeResponse(w io.Writer, resp mcp.JSONRPCResponse) error {
	b, err := json.Marshal(resp)
	if err != nil {
		return fmt.Errorf("proxy: marshal response: %w", err)
	}
	_, err = writeLine(w, b)
	return err
}
