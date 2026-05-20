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
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sync"
	"sync/atomic"

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
// runtime. Implementations live outside this package (issue #29 will add a
// TTY-backed approver in internal/approval). The proxy ships with a default
// DenyAllApprover so the intercept loop never silently treats ask as allow.
type Approver interface {
	Request(ctx context.Context, call policy.ToolCall) (bool, error)
}

// DenyAllApprover converts every ask decision into deny. Use this in
// non-interactive contexts (CI, --no-interactive) until issue #29 lands a
// real TTY approver.
type DenyAllApprover struct{}

// Request always returns (false, nil) — an unattended proxy must default-deny.
func (DenyAllApprover) Request(context.Context, policy.ToolCall) (bool, error) {
	return false, nil
}

// Options configures Run. Engine and AuditWriter are required when
// Passthrough is false; the rest have sensible defaults documented below.
type Options struct {
	// Engine evaluates each intercepted tools/call. Required unless
	// Passthrough is true.
	Engine *engine.Engine

	// AuditWriter records evaluation decisions. Must be non-nil — pass an
	// audit.NewWriter(io.Discard) if you do not need persistence. Audit
	// records are written before the forwarding decision is acted on so
	// the audit trail reflects every decision the engine made.
	AuditWriter *audit.Writer

	// Approver handles ask decisions. Defaults to DenyAllApprover.
	Approver Approver

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
	if !opts.Passthrough && opts.Engine == nil {
		return errors.New("proxy: Engine is required when not in passthrough mode")
	}
	if opts.AuditWriter == nil {
		return errors.New("proxy: AuditWriter is required (use audit.NewWriter(io.Discard) to disable)")
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

	r := newRelay(opts)
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
	return opts
}

// relay holds per-Run mutable state (the call counter). It is intentionally
// not exported: callers should drive the proxy via Run.
type relay struct {
	opts        Options
	callCounter uint64
}

func newRelay(opts Options) *relay {
	return &relay{opts: opts}
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

	params, perr := mcp.ParseToolCallParams(req.Params)
	if perr != nil {
		// Malformed tools/call: answer the agent with a well-formed error
		// instead of forwarding garbage to the subprocess. No audit event
		// here because the engine never saw a valid call.
		return writeResponse(agentStdout, mcp.InvalidParamsError(req.ID, perr.Error()))
	}

	fallback := fmt.Sprintf("call-%d", atomic.AddUint64(&r.callCounter, 1))
	callID := mcp.CallIDFromRequestID(req.ID, fallback)
	call := params.ToToolCall(callID)
	result, event := r.opts.Engine.Evaluate(call)

	// Audit first so the decision is durable even if the forwarding step
	// fails (e.g. subprocess pipe closed mid-relay).
	if writeErr := r.opts.AuditWriter.Write(event); writeErr != nil {
		fmt.Fprintln(r.opts.Logger, "proxy: audit write:", writeErr)
	}

	switch result.Decision {
	case policy.DecisionAllow:
		_, err := writeLine(subStdin, line)
		return err
	case policy.DecisionDeny:
		return writeResponse(agentStdout, mcp.BlockedByPolicyError(req.ID, result.Reason))
	case policy.DecisionAsk:
		approved, aerr := r.opts.Approver.Request(ctx, call)
		if aerr != nil {
			return writeResponse(agentStdout,
				mcp.BlockedByPolicyError(req.ID, "approval error: "+aerr.Error()))
		}
		if approved {
			_, err := writeLine(subStdin, line)
			return err
		}
		return writeResponse(agentStdout,
			mcp.BlockedByPolicyError(req.ID, result.Reason+" (denied via ask)"))
	default:
		// Unknown decision (engine extension): default-deny so a future
		// decision value cannot silently widen the allow set.
		return writeResponse(agentStdout,
			mcp.BlockedByPolicyError(req.ID,
				"unknown decision: "+string(result.Decision)))
	}
}

func writeLine(w io.Writer, line []byte) (int, error) {
	// Build a single contiguous slice to avoid two Write syscalls that could
	// interleave with another goroutine writing to the same Stdout.
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
