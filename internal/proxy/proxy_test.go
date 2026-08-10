package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dgenio/agentfence/internal/approval"
	"github.com/dgenio/agentfence/internal/audit"
	"github.com/dgenio/agentfence/internal/engine"
	"github.com/dgenio/agentfence/internal/mcp"
	"github.com/dgenio/agentfence/internal/policy"
)

// fakeEcho is a tiny MCP-server-shaped subprocess: it reads JSON-RPC lines
// from stdin and echoes a canned result for each one. Driven via the re-exec
// trick — see TestMain.
const fakeEchoEnv = "AGENTFENCE_PROXY_FAKE_ECHO"

func TestMain(m *testing.M) {
	if os.Getenv(fakeEchoEnv) == "1" {
		runFakeEchoServer()
		return
	}
	os.Exit(m.Run())
}

func runFakeEchoServer() {
	dec := json.NewDecoder(os.Stdin)
	enc := json.NewEncoder(os.Stdout)
	for {
		var req mcp.JSONRPCRequest
		if err := dec.Decode(&req); err != nil {
			if errors.Is(err, io.EOF) {
				return
			}
			// On a malformed line, write a parse-error response so tests
			// can distinguish "proxy forwarded garbage" from "subprocess
			// crashed".
			_ = enc.Encode(mcp.JSONRPCResponse{
				JSONRPC: mcp.JSONRPCVersion,
				ID:      json.RawMessage(`null`),
				Error: &mcp.JSONRPCError{
					Code:    mcp.ErrorCodeParseError,
					Message: err.Error(),
				},
			})
			continue
		}
		_ = enc.Encode(mcp.JSONRPCResponse{
			JSONRPC: mcp.JSONRPCVersion,
			ID:      req.ID,
			Result:  json.RawMessage(`{"echoed":true}`),
		})
	}
}

// allowDenyAskPolicy returns a policy that exercises every decision path:
// filesystem.read → allow, filesystem.write → deny, github.create_issue → ask,
// everything else → deny by default.
func allowDenyAskPolicy(t *testing.T) policy.Policy {
	t.Helper()
	p, err := policy.ParsePolicy([]byte(`version: "0.1"
defaults:
  decision: deny
tools:
  filesystem.read:
    decision: allow
  filesystem.write:
    decision: deny
  github.create_issue:
    decision: ask
`))
	if err != nil {
		t.Fatalf("ParsePolicy: %v", err)
	}
	return p
}

func newTestRelay(t *testing.T, approver Approver, passthrough bool) (*relay, *bytes.Buffer, *bytes.Buffer, *bytes.Buffer) {
	t.Helper()
	p := allowDenyAskPolicy(t)
	eng, err := engine.New(p)
	if err != nil {
		t.Fatalf("engine.New: %v", err)
	}
	auditBuf := &bytes.Buffer{}
	subBuf := &bytes.Buffer{}
	agentBuf := &bytes.Buffer{}
	aw := audit.NewWriterOptions(auditBuf, audit.Options{SessionID: "test-session"})
	opts := Options{
		Engine:      eng,
		AuditWriter: aw,
		Approver:    approver,
		Passthrough: passthrough,
	}
	opts = applyDefaults(opts)
	return newRelay(opts, eng.NewSession()), agentBuf, subBuf, auditBuf
}

// newTestRelayWith builds a relay like newTestRelay but lets a test set the
// approval timeout and the non-interactive flag, so the ask resolution paths
// (timeout, non-interactive deny) can be driven deterministically.
func newTestRelayWith(t *testing.T, approver Approver, timeout time.Duration, noInteractive bool) (*relay, *bytes.Buffer, *bytes.Buffer, *bytes.Buffer) {
	t.Helper()
	eng, err := engine.New(allowDenyAskPolicy(t))
	if err != nil {
		t.Fatalf("engine.New: %v", err)
	}
	auditBuf := &bytes.Buffer{}
	subBuf := &bytes.Buffer{}
	agentBuf := &bytes.Buffer{}
	opts := Options{
		Engine:          eng,
		AuditWriter:     audit.NewWriterOptions(auditBuf, audit.Options{SessionID: "test-session"}),
		Approver:        approver,
		ApprovalTimeout: timeout,
		NoInteractive:   noInteractive,
	}
	opts = applyDefaults(opts)
	return newRelay(opts, eng.NewSession()), agentBuf, subBuf, auditBuf
}

// blockingApprover blocks until its context is done, then returns the context
// error. It models an operator who never answers, exercising the
// approval-timeout path.
type blockingApprover struct{}

func (blockingApprover) Request(ctx context.Context, _ policy.ToolCall) (bool, error) {
	<-ctx.Done()
	return false, ctx.Err()
}

// helperRequest builds a minimal JSON-RPC tools/call line. id may be any JSON
// fragment ("1", `"abc"`, etc.).
func helperRequest(t *testing.T, id, name, arguments string) []byte {
	t.Helper()
	if arguments == "" {
		arguments = "{}"
	}
	body := `{"jsonrpc":"2.0","id":` + id + `,"method":"tools/call","params":{"name":"` + name + `","arguments":` + arguments + `}}`
	if !json.Valid([]byte(body)) {
		t.Fatalf("test bug: helperRequest produced invalid JSON: %s", body)
	}
	return []byte(body)
}

func TestProcessAgentLineAllowForwards(t *testing.T) {
	r, agent, sub, audit := newTestRelay(t, DenyAllApprover{}, false /*passthrough*/)
	// MCP 2026-07-28 is stateless: client identity/capabilities travel in
	// request _meta instead of an initialize handshake. The proxy evaluates the
	// typed tool fields but must forward the complete original request intact.
	line := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"filesystem.read","arguments":{"path":"README.md"},"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{},"io.modelcontextprotocol/clientInfo":{"name":"proxy-test","version":"1"}}}}`)
	if err := r.processAgentLine(context.Background(), line, sub, agent); err != nil {
		t.Fatalf("processAgentLine: %v", err)
	}
	if !bytes.Contains(sub.Bytes(), []byte(`"method":"tools/call"`)) {
		t.Errorf("allow path must forward the request to subprocess; sub=%q", sub.String())
	}
	if !bytes.Contains(sub.Bytes(), []byte(`"io.modelcontextprotocol/protocolVersion":"2026-07-28"`)) ||
		!bytes.Contains(sub.Bytes(), []byte(`"io.modelcontextprotocol/clientCapabilities":{}`)) ||
		!bytes.Contains(sub.Bytes(), []byte(`"io.modelcontextprotocol/clientInfo"`)) {
		t.Errorf("allow path must preserve stateless MCP request metadata; sub=%q", sub.String())
	}
	if agent.Len() != 0 {
		t.Errorf("allow path must not write to agent stdout; got %q", agent.String())
	}
	if !bytes.Contains(audit.Bytes(), []byte(`"decision":"allow"`)) {
		t.Errorf("audit must record an allow event; got %q", audit.String())
	}
}

func TestProcessAgentLineDenyBlocks(t *testing.T) {
	r, agent, sub, auditBuf := newTestRelay(t, DenyAllApprover{}, false)
	line := helperRequest(t, `2`, "filesystem.write", `{"path":".env","content":"x"}`)
	if err := r.processAgentLine(context.Background(), line, sub, agent); err != nil {
		t.Fatalf("processAgentLine: %v", err)
	}
	if sub.Len() != 0 {
		t.Errorf("deny path must NOT forward to subprocess; got %q", sub.String())
	}

	var resp mcp.JSONRPCResponse
	if err := json.Unmarshal(bytes.TrimRight(agent.Bytes(), "\n"), &resp); err != nil {
		t.Fatalf("agent stdout is not valid JSON-RPC: %v (raw=%q)", err, agent.String())
	}
	if resp.Error == nil || resp.Error.Code != mcp.ErrorCodeBlockedByPolicy {
		t.Errorf("expected blocked-by-policy error, got %+v", resp.Error)
	}
	if string(resp.ID) != "2" {
		t.Errorf("response ID = %s, want 2 (must echo the request ID)", string(resp.ID))
	}
	if !bytes.Contains(auditBuf.Bytes(), []byte(`"decision":"deny"`)) {
		t.Errorf("audit must record a deny event; got %q", auditBuf.String())
	}
}

type yesApprover struct{}

func (yesApprover) Request(context.Context, policy.ToolCall) (bool, error) { return true, nil }

type erroringApprover struct{}

func (erroringApprover) Request(context.Context, policy.ToolCall) (bool, error) {
	return false, errors.New("user terminated")
}

func TestProcessAgentLineAskApproved(t *testing.T) {
	r, agent, sub, auditBuf := newTestRelay(t, yesApprover{}, false)
	line := helperRequest(t, `3`, "github.create_issue", `{"title":"hi"}`)
	if err := r.processAgentLine(context.Background(), line, sub, agent); err != nil {
		t.Fatalf("processAgentLine: %v", err)
	}
	if sub.Len() == 0 {
		t.Errorf("approved ask must forward to subprocess; got empty sub stdin")
	}
	if agent.Len() != 0 {
		t.Errorf("approved ask must not write to agent stdout; got %q", agent.String())
	}
	if !bytes.Contains(auditBuf.Bytes(), []byte(`"decision":"allow"`)) {
		t.Errorf("approved ask must audit decision allow; got %q", auditBuf.String())
	}
	if !bytes.Contains(auditBuf.Bytes(), []byte(approval.ReasonApprovedInteractively)) {
		t.Errorf("approved ask must audit the approval reason; got %q", auditBuf.String())
	}
}

func TestProcessAgentLineAskDenied(t *testing.T) {
	r, agent, sub, auditBuf := newTestRelay(t, DenyAllApprover{}, false)
	line := helperRequest(t, `4`, "github.create_issue", `{"title":"hi"}`)
	if err := r.processAgentLine(context.Background(), line, sub, agent); err != nil {
		t.Fatalf("processAgentLine: %v", err)
	}
	if sub.Len() != 0 {
		t.Errorf("denied ask must NOT forward to subprocess; got %q", sub.String())
	}
	if !strings.Contains(agent.String(), approval.ReasonDeniedInteractively) {
		t.Errorf("denied ask must report the interactive-deny reason; got %q", agent.String())
	}
	if !bytes.Contains(auditBuf.Bytes(), []byte(`"decision":"deny"`)) {
		t.Errorf("denied ask must audit decision deny; got %q", auditBuf.String())
	}
}

func TestProcessAgentLineAskErrors(t *testing.T) {
	r, agent, sub, auditBuf := newTestRelay(t, erroringApprover{}, false)
	line := helperRequest(t, `5`, "github.create_issue", `{"title":"hi"}`)
	if err := r.processAgentLine(context.Background(), line, sub, agent); err != nil {
		t.Fatalf("processAgentLine: %v", err)
	}
	if sub.Len() != 0 {
		t.Errorf("approver error must NOT forward to subprocess; got %q", sub.String())
	}
	// The agent sees the canonical I/O-error reason, not the internal error text.
	if !strings.Contains(agent.String(), approval.ReasonApprovalIOError) {
		t.Errorf("approver error must surface the canonical reason; got %q", agent.String())
	}
	if strings.Contains(agent.String(), "user terminated") {
		t.Errorf("internal approver error text must not leak to the agent; got %q", agent.String())
	}
	if !bytes.Contains(auditBuf.Bytes(), []byte(`"decision":"deny"`)) {
		t.Errorf("approver error must audit decision deny; got %q", auditBuf.String())
	}
}

// TestProcessAgentLineAskTimeout drives the approval-timeout path: a blocking
// approver plus a short ApprovalTimeout must auto-deny with the timeout reason.
func TestProcessAgentLineAskTimeout(t *testing.T) {
	r, agent, sub, auditBuf := newTestRelayWith(t, blockingApprover{}, 20*time.Millisecond, false)
	line := helperRequest(t, `6`, "github.create_issue", `{"title":"hi"}`)
	if err := r.processAgentLine(context.Background(), line, sub, agent); err != nil {
		t.Fatalf("processAgentLine: %v", err)
	}
	if sub.Len() != 0 {
		t.Errorf("timed-out ask must NOT forward to subprocess; got %q", sub.String())
	}
	if !strings.Contains(agent.String(), approval.ReasonApprovalTimeout) {
		t.Errorf("timed-out ask must report the timeout reason; got %q", agent.String())
	}
	if !bytes.Contains(auditBuf.Bytes(), []byte(`"decision":"deny"`)) {
		t.Errorf("timed-out ask must audit decision deny; got %q", auditBuf.String())
	}
}

// TestProcessAgentLineAskNonInteractive verifies that with NoInteractive set, a
// denied ask is attributed to the non-interactive reason.
func TestProcessAgentLineAskNonInteractive(t *testing.T) {
	r, agent, sub, _ := newTestRelayWith(t, DenyAllApprover{}, 0, true /*noInteractive*/)
	line := helperRequest(t, `7`, "github.create_issue", `{"title":"hi"}`)
	if err := r.processAgentLine(context.Background(), line, sub, agent); err != nil {
		t.Fatalf("processAgentLine: %v", err)
	}
	if !strings.Contains(agent.String(), approval.ReasonNonInteractive) {
		t.Errorf("non-interactive ask must report the non-interactive reason; got %q", agent.String())
	}
}

// TestProcessAgentLineAskNotificationDropped verifies that an ask decision on a
// JSON-RPC notification (no id) is dropped without a synthesized response,
// since the spec forbids replying to notifications.
func TestProcessAgentLineAskNotificationDropped(t *testing.T) {
	r, agent, sub, _ := newTestRelay(t, DenyAllApprover{}, false)
	// tools/call with no id is a notification.
	line := []byte(`{"jsonrpc":"2.0","method":"tools/call","params":{"name":"github.create_issue","arguments":{"title":"hi"}}}`)
	if err := r.processAgentLine(context.Background(), line, sub, agent); err != nil {
		t.Fatalf("processAgentLine: %v", err)
	}
	if sub.Len() != 0 {
		t.Errorf("denied ask notification must NOT forward to subprocess; got %q", sub.String())
	}
	if agent.Len() != 0 {
		t.Errorf("ask notification must not produce a response; got %q", agent.String())
	}
}

func TestProcessAgentLineNonToolsCallForwards(t *testing.T) {
	r, agent, sub, _ := newTestRelay(t, DenyAllApprover{}, false)
	line := []byte(`{"jsonrpc":"2.0","id":99,"method":"initialize","params":{}}`)
	if err := r.processAgentLine(context.Background(), line, sub, agent); err != nil {
		t.Fatalf("processAgentLine: %v", err)
	}
	if !bytes.Equal(bytes.TrimRight(sub.Bytes(), "\n"), line) {
		t.Errorf("non-tools/call line must be forwarded verbatim;\n got %q\nwant %q",
			sub.String(), line)
	}
	if agent.Len() != 0 {
		t.Errorf("non-tools/call must not produce an error response; got %q", agent.String())
	}
}

func TestProcessAgentLineMalformedJSONForwards(t *testing.T) {
	// AgentFence is not the JSON-RPC parser of record. A non-JSON line is
	// forwarded so the subprocess (which IS the parser of record) reports
	// the error. This keeps the proxy transparent to clients that lean on
	// the server's diagnostics.
	r, agent, sub, _ := newTestRelay(t, DenyAllApprover{}, false)
	line := []byte(`not valid json`)
	if err := r.processAgentLine(context.Background(), line, sub, agent); err != nil {
		t.Fatalf("processAgentLine: %v", err)
	}
	if !bytes.Equal(bytes.TrimRight(sub.Bytes(), "\n"), line) {
		t.Errorf("malformed JSON must be forwarded verbatim; got %q", sub.String())
	}
}

func TestProcessAgentLineMalformedParamsReturnsInvalidParams(t *testing.T) {
	r, agent, sub, _ := newTestRelay(t, DenyAllApprover{}, false)
	// Well-formed JSON-RPC request, but params is missing the required "name".
	line := []byte(`{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{}}`)
	if err := r.processAgentLine(context.Background(), line, sub, agent); err != nil {
		t.Fatalf("processAgentLine: %v", err)
	}
	if sub.Len() != 0 {
		t.Errorf("malformed tools/call params must NOT be forwarded; got %q", sub.String())
	}
	var resp mcp.JSONRPCResponse
	if err := json.Unmarshal(bytes.TrimRight(agent.Bytes(), "\n"), &resp); err != nil {
		t.Fatalf("agent stdout is not valid JSON-RPC: %v", err)
	}
	if resp.Error == nil || resp.Error.Code != mcp.ErrorCodeInvalidParams {
		t.Errorf("expected InvalidParams (%d) response; got %+v",
			mcp.ErrorCodeInvalidParams, resp.Error)
	}
}

// TestNotificationDenyDropsInsteadOfResponding verifies the JSON-RPC §4.1
// rule: notifications (requests without an id) MUST NOT receive a response.
// A deny on a notification audits the decision but drops the line.
func TestNotificationDenyDropsInsteadOfResponding(t *testing.T) {
	r, agent, sub, audit := newTestRelay(t, DenyAllApprover{}, false)
	// id field omitted entirely — this is a notification.
	line := []byte(`{"jsonrpc":"2.0","method":"tools/call","params":{"name":"filesystem.write","arguments":{"path":".env"}}}`)
	if err := r.processAgentLine(context.Background(), line, sub, agent); err != nil {
		t.Fatalf("processAgentLine: %v", err)
	}
	if sub.Len() != 0 {
		t.Errorf("denied notification must NOT forward to subprocess; got %q", sub.String())
	}
	if agent.Len() != 0 {
		t.Errorf("denied notification must NOT synthesize a response; got %q", agent.String())
	}
	if !bytes.Contains(audit.Bytes(), []byte(`"decision":"deny"`)) {
		t.Errorf("denied notification must still audit; got %q", audit.String())
	}
}

func TestNotificationAskDeniedDropsInsteadOfResponding(t *testing.T) {
	r, agent, sub, _ := newTestRelay(t, DenyAllApprover{}, false)
	line := []byte(`{"jsonrpc":"2.0","method":"tools/call","params":{"name":"github.create_issue","arguments":{"title":"hi"}}}`)
	if err := r.processAgentLine(context.Background(), line, sub, agent); err != nil {
		t.Fatalf("processAgentLine: %v", err)
	}
	if sub.Len() != 0 || agent.Len() != 0 {
		t.Errorf("denied ask-notification must drop silently; sub=%q agent=%q",
			sub.String(), agent.String())
	}
}

func TestNotificationAllowForwards(t *testing.T) {
	r, agent, sub, _ := newTestRelay(t, DenyAllApprover{}, false)
	// Same shape as the deny test but for an allowed tool.
	line := []byte(`{"jsonrpc":"2.0","method":"tools/call","params":{"name":"filesystem.read","arguments":{"path":"README.md"}}}`)
	if err := r.processAgentLine(context.Background(), line, sub, agent); err != nil {
		t.Fatalf("processAgentLine: %v", err)
	}
	if sub.Len() == 0 {
		t.Errorf("allowed notification must still forward to subprocess")
	}
	if agent.Len() != 0 {
		t.Errorf("allowed notification must not produce a response; got %q", agent.String())
	}
}

func TestNotificationWithNullIDIsTreatedAsNotification(t *testing.T) {
	// JSON-RPC technically distinguishes "id":null from a missing id, but
	// the proxy treats both as notifications because there is no useful
	// response identifier to echo and some clients treat null id as
	// fire-and-forget.
	r, agent, sub, _ := newTestRelay(t, DenyAllApprover{}, false)
	line := []byte(`{"jsonrpc":"2.0","id":null,"method":"tools/call","params":{"name":"filesystem.write","arguments":{"path":".env"}}}`)
	if err := r.processAgentLine(context.Background(), line, sub, agent); err != nil {
		t.Fatalf("processAgentLine: %v", err)
	}
	if sub.Len() != 0 || agent.Len() != 0 {
		t.Errorf("null-id deny must drop silently; sub=%q agent=%q",
			sub.String(), agent.String())
	}
}

func TestNotificationMalformedParamsDropsInsteadOfResponding(t *testing.T) {
	r, agent, sub, audit := newTestRelay(t, DenyAllApprover{}, false)
	// tools/call notification with no name → InvalidParams in the request
	// path, must drop silently here.
	line := []byte(`{"jsonrpc":"2.0","method":"tools/call","params":{}}`)
	if err := r.processAgentLine(context.Background(), line, sub, agent); err != nil {
		t.Fatalf("processAgentLine: %v", err)
	}
	if sub.Len() != 0 || agent.Len() != 0 {
		t.Errorf("malformed notification must drop silently; sub=%q agent=%q",
			sub.String(), agent.String())
	}
	// No audit event either — engine never saw a valid call.
	if audit.Len() != 0 {
		t.Errorf("malformed notification must not produce an audit event; got %q", audit.String())
	}
}

func TestLockedWriterSerialisesConcurrentWrites(t *testing.T) {
	// Race-detector-targeted test: many goroutines writing to a
	// lockedWriter must serialise into a coherent byte stream.
	var underlying bytes.Buffer
	lw := &lockedWriter{w: &underlying}
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			payload := []byte("frame-" + strings.Repeat("x", 16) + "-end\n")
			_ = payload
			payload = append([]byte{}, []byte("frame-")...)
			payload = append(payload, byte('0'+(i%10)))
			payload = append(payload, []byte("-end\n")...)
			if _, err := lw.Write(payload); err != nil {
				t.Errorf("Write: %v", err)
			}
		}(i)
	}
	wg.Wait()
	// Every line must begin with "frame-" and end with "-end" — if writes
	// interleaved we would see corrupted frames.
	for i, line := range strings.Split(strings.TrimRight(underlying.String(), "\n"), "\n") {
		if !strings.HasPrefix(line, "frame-") || !strings.HasSuffix(line, "-end") {
			t.Errorf("line %d corrupted by interleaving: %q", i, line)
		}
	}
}

func TestProcessAgentLinePassthroughForwardsEverything(t *testing.T) {
	r, agent, sub, audit := newTestRelay(t, DenyAllApprover{}, true /*passthrough*/)
	// Even a deny-policy tool is forwarded in passthrough mode — that's the
	// whole point of the skeleton mode (validate the relay without
	// enforcement).
	line := helperRequest(t, `8`, "filesystem.write", `{"path":".env"}`)
	if err := r.processAgentLine(context.Background(), line, sub, agent); err != nil {
		t.Fatalf("processAgentLine: %v", err)
	}
	if !bytes.Contains(sub.Bytes(), []byte(`"method":"tools/call"`)) {
		t.Errorf("passthrough must forward tools/call lines; got %q", sub.String())
	}
	if agent.Len() != 0 {
		t.Errorf("passthrough must not synthesize responses; got %q", agent.String())
	}
	if audit.Len() != 0 {
		t.Errorf("passthrough must not write audit events; got %q", audit.String())
	}
}

func TestRunRequiresCommand(t *testing.T) {
	err := Run(context.Background(), "", nil, Options{
		Engine:      nil,
		AuditWriter: audit.NewWriter(io.Discard),
		Passthrough: true,
	})
	if err == nil || !strings.Contains(err.Error(), "command is required") {
		t.Errorf("expected 'command is required' error, got %v", err)
	}
}

func TestRunRequiresEngineWhenNotPassthrough(t *testing.T) {
	err := Run(context.Background(), os.Args[0], nil, Options{
		AuditWriter: audit.NewWriter(io.Discard),
		Passthrough: false,
	})
	if err == nil || !strings.Contains(err.Error(), "Engine is required") {
		t.Errorf("expected Engine-required error, got %v", err)
	}
}

func TestRunRequiresAuditWriterWhenEnforcing(t *testing.T) {
	p := allowDenyAskPolicy(t)
	eng, err := engine.New(p)
	if err != nil {
		t.Fatalf("engine.New: %v", err)
	}
	err = Run(context.Background(), os.Args[0], nil, Options{
		Engine:      eng,
		AuditWriter: nil,
		Passthrough: false,
	})
	if err == nil || !strings.Contains(err.Error(), "AuditWriter is required") {
		t.Errorf("expected AuditWriter-required error in enforcement mode, got %v", err)
	}
}

// TestRunAllowsNilAuditWriterInPassthrough verifies that the passthrough
// skeleton does not require an audit writer (its docstring promise). We
// can't realistically spawn a subprocess in this short test, so we provide
// an empty command name to force the "command is required" failure
// *after* the audit-writer check — proving the audit check did not fire.
func TestRunAllowsNilAuditWriterInPassthrough(t *testing.T) {
	err := Run(context.Background(), "", nil, Options{
		AuditWriter: nil,
		Passthrough: true,
	})
	if err == nil || !strings.Contains(err.Error(), "command is required") {
		t.Errorf("passthrough must tolerate a nil AuditWriter; got %v", err)
	}
}

// TestRunEndToEndAllow drives Run with a real subprocess (the fakeEcho helper)
// and validates that an allowed tools/call reaches it and the result is
// relayed back.
func TestRunEndToEndAllow(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("subprocess stdio relay E2E test relies on POSIX-shaped pipes")
	}

	p := allowDenyAskPolicy(t)
	eng, err := engine.New(p)
	if err != nil {
		t.Fatalf("engine.New: %v", err)
	}

	agentStdinR, agentStdinW := io.Pipe()
	agentStdoutBuf := &lockedBuffer{}
	aw := audit.NewWriter(io.Discard)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	opts := Options{
		Engine:      eng,
		AuditWriter: aw,
		Stdin:       agentStdinR,
		Stdout:      agentStdoutBuf,
		Stderr:      io.Discard,
	}

	// Run the proxy in a goroutine so we can feed it on agentStdinW.
	done := make(chan error, 1)
	go func() {
		done <- runWithEnv(ctx, os.Args[0], []string{"-test.run=^$"},
			[]string{fakeEchoEnv + "=1"}, opts)
	}()

	// Send one allow-able request, then close stdin to let the subprocess
	// reach EOF and exit cleanly.
	req := helperRequest(t, `42`, "filesystem.read", `{"path":"README.md"}`)
	if _, err := agentStdinW.Write(append(req, '\n')); err != nil {
		t.Fatalf("write request: %v", err)
	}
	// Wait until the response shows up before closing stdin, so the
	// relaySubToAgent goroutine has flushed it onto agentStdoutBuf.
	waitFor(t, func() bool {
		return strings.Contains(agentStdoutBuf.String(), `"echoed":true`)
	}, "fake server response on agent stdout")
	if err := agentStdinW.Close(); err != nil {
		t.Fatalf("close agent stdin: %v", err)
	}

	if err := <-done; err != nil {
		t.Fatalf("Run returned: %v", err)
	}

	if !strings.Contains(agentStdoutBuf.String(), `"echoed":true`) {
		t.Errorf("expected fake server response on agent stdout; got %q",
			agentStdoutBuf.String())
	}
}

// runWithEnv is a thin wrapper around Run that lets the test inject an env
// var into the spawned subprocess. It re-implements Run's subprocess setup so
// the test can pass extra env without exposing it on the public API.
func runWithEnv(ctx context.Context, command string, args, extraEnv []string, opts Options) error {
	opts = applyDefaults(opts)
	cmd := exec.CommandContext(ctx, command, args...)
	cmd.Env = append(os.Environ(), extraEnv...)
	subIn, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	subOut, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	cmd.Stderr = opts.Stderr
	if err := cmd.Start(); err != nil {
		return err
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
		defer subIn.Close()
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

// lockedBuffer is a tiny thread-safe bytes.Buffer wrapper. The proxy's two
// relay goroutines both write to the agent's stdout (subproc->agent for
// success, agent->agent for synthesised errors), so a plain bytes.Buffer is
// unsafe under -race.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// waitFor polls cond up to ~2 seconds. The proxy's two relay goroutines are
// inherently async with respect to the test, so a short poll loop is cleaner
// than threading channels through the public API.
func waitFor(t *testing.T, cond func() bool, what string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for: %s", what)
}
