// Package httpproxy implements the AgentFence MCP streamable-HTTP proxy.
//
// It is the HTTP/SSE counterpart to the stdio proxy in internal/proxy: a
// reverse proxy that sits in front of a remote MCP server reachable over HTTP.
// Every POST body that parses as a JSON-RPC tools/call is evaluated against the
// policy engine before being forwarded, with the same decision, redaction,
// approval, and hash-chained audit semantics as the stdio proxy:
//
//   - allow → the request is forwarded to the upstream MCP server and its
//     response (including a streamed text/event-stream body) is relayed back.
//   - deny  → a JSON-RPC error response (ErrorCodeBlockedByPolicy) is returned
//     and the upstream server never sees the request.
//   - ask   → the Approver decides; an approved call is forwarded, a denied one
//     becomes the same error response as a direct deny.
//
// Any other request — a non-POST, a non-JSON-RPC body, or a JSON-RPC method
// other than tools/call — is forwarded transparently so initialize, ping,
// notifications, and the SSE GET channel keep working.
//
// Request-body edge cases are handled fail-closed rather than forwarded
// uninspected:
//
//   - batch  → a JSON-RPC batch (array) body is refused by default
//     (Options.OnBatch = BatchReject), or every member is gated and the batch
//     forwarded only if all are allowed (BatchEvaluate).
//   - oversize → a body over maxBodyBytes is refused (JSON-RPC error envelope
//     when it looked like JSON-RPC, else HTTP 413).
//   - unparseable → forwarded by default (Options.OnUnparsed = UnparsedForward)
//     or refused (UnparsedReject).
//
// When Options.AuthToken is set, every request must carry a matching
// "Authorization: Bearer <token>" header or it is refused with HTTP 401.
//
// Because JSON-RPC carries errors in a 200 response envelope, a policy denial
// is returned as HTTP 200 with a JSON-RPC error body, not an HTTP error status;
// upstream/proxy failures are surfaced the same way with distinct error codes
// (see internal/mcp). See docs/threat-model.md for the HTTP-specific surface
// (auth, TLS, and multi-client session handling) that the stdio transport does
// not have.
package httpproxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"time"

	"github.com/dgenio/agentfence/internal/approval"
	"github.com/dgenio/agentfence/internal/audit"
	"github.com/dgenio/agentfence/internal/engine"
	"github.com/dgenio/agentfence/internal/mcp"
	"github.com/dgenio/agentfence/internal/policy"
)

// maxBodyBytes caps how much of a request body the proxy buffers to inspect a
// tools/call. MCP messages can carry base64 blobs and large structured
// arguments, so the limit is generous; bodies larger than this are rejected
// rather than forwarded uninspected (which would bypass policy).
const maxBodyBytes = 16 * 1024 * 1024 // 16 MiB

// maxObserveBytes caps how much of an allowed tool's response body is captured
// for taint observation, bounding memory on large or streamed results.
const maxObserveBytes = 256 * 1024 // 256 KiB

// Approver decides whether an "ask" decision becomes an allow or deny at
// runtime. It is an alias for approval.Approver, the single contract shared by
// the HTTP proxy, the stdio proxy, and the check command, so one approver
// implementation (e.g. approval.TTYApprover) wires into every call site.
type Approver = approval.Approver

// DenyAllApprover converts every ask decision into deny. It is an alias for
// approval.DenyAllApprover — the shared fail-closed default used in
// non-interactive contexts (CI, --no-interactive).
type DenyAllApprover = approval.DenyAllApprover

// BatchPolicy controls how the proxy treats a JSON-RPC batch (array) body. The
// single-request parser does not model batches, so without a policy a batch
// would be forwarded uninspected and could smuggle a denied tools/call.
type BatchPolicy string

const (
	// BatchReject refuses any batch body with a JSON-RPC error. This is the
	// fail-closed default.
	BatchReject BatchPolicy = "reject"
	// BatchEvaluate evaluates every tools/call member against the policy and
	// forwards the whole batch only if all members are allowed; if any member
	// is denied (or an ask is not approved) the entire batch is rejected.
	BatchEvaluate BatchPolicy = "evaluate"
)

// UnparsedPolicy controls how the proxy treats a POST body that does not parse
// as a JSON-RPC request at all.
type UnparsedPolicy string

const (
	// UnparsedForward forwards an unparseable body transparently (the historical
	// behavior) so non-JSON-RPC traffic the proxy does not model keeps working.
	UnparsedForward UnparsedPolicy = "forward"
	// UnparsedReject refuses an unparseable body instead of forwarding it
	// uninspected.
	UnparsedReject UnparsedPolicy = "reject"
)

// Options configures NewHandler. Engine, AuditWriter, and Upstream are required
// unless Passthrough is true.
type Options struct {
	// Engine evaluates each intercepted tools/call. Required unless Passthrough.
	Engine *engine.Engine
	// AuditWriter records evaluation decisions. Required unless Passthrough.
	AuditWriter *audit.Writer
	// Approver handles ask decisions. Defaults to DenyAllApprover.
	Approver Approver
	// ApprovalTimeout bounds how long a single ask prompt may wait before the
	// call is auto-denied with the approval-timeout reason. Zero waits
	// indefinitely (subject to request-context cancellation).
	ApprovalTimeout time.Duration
	// NoInteractive records that interactive approval was disabled, so a denied
	// ask is attributed to the non-interactive reason rather than an explicit
	// operator rejection. Callers pass DenyAllApprover when this is set.
	NoInteractive bool
	// Upstream is the base URL of the MCP server to proxy to. Required.
	Upstream *url.URL
	// Passthrough forwards every request without policy evaluation. Use only to
	// validate the relay; production deployments should leave it false.
	Passthrough bool
	// Debug logs every proxied request line to Logger.
	Debug bool
	// Logger receives proxy-internal diagnostics. Defaults to io.Discard.
	Logger io.Writer
	// Client is the HTTP client used for upstream requests. Defaults to a
	// client with no timeout (so streamed/SSE responses are not cut off).
	Client *http.Client
	// OnBatch controls JSON-RPC batch (array) bodies. Defaults to BatchReject.
	OnBatch BatchPolicy
	// OnUnparsed controls POST bodies that do not parse as JSON-RPC. Defaults
	// to UnparsedForward.
	OnUnparsed UnparsedPolicy
	// AuthToken, when non-empty, requires every request to carry an
	// "Authorization: Bearer <token>" header matching it; requests without a
	// valid token are refused with HTTP 401. Empty disables authentication.
	AuthToken string
}

// Handler is the http.Handler that proxies and gates MCP-over-HTTP traffic.
type Handler struct {
	opts        Options
	sess        *engine.Session
	client      *http.Client
	callCounter uint64
}

// NewHandler validates opts and returns a ready Handler.
func NewHandler(opts Options) (*Handler, error) {
	if opts.Upstream == nil {
		return nil, errors.New("httpproxy: Upstream is required")
	}
	if opts.Upstream.Scheme == "" || opts.Upstream.Host == "" {
		return nil, fmt.Errorf("httpproxy: Upstream %q must be an absolute URL with scheme and host", opts.Upstream)
	}
	if !opts.Passthrough {
		if opts.Engine == nil {
			return nil, errors.New("httpproxy: Engine is required when not in passthrough mode")
		}
		if opts.AuditWriter == nil {
			return nil, errors.New("httpproxy: AuditWriter is required when not in passthrough mode (use audit.NewWriter(io.Discard) to disable)")
		}
	}
	if opts.Approver == nil {
		opts.Approver = DenyAllApprover{}
	}
	if opts.OnBatch == "" {
		opts.OnBatch = BatchReject
	}
	switch opts.OnBatch {
	case BatchReject, BatchEvaluate:
	default:
		return nil, fmt.Errorf("httpproxy: invalid OnBatch %q (want %q or %q)", opts.OnBatch, BatchReject, BatchEvaluate)
	}
	if opts.OnUnparsed == "" {
		opts.OnUnparsed = UnparsedForward
	}
	switch opts.OnUnparsed {
	case UnparsedForward, UnparsedReject:
	default:
		return nil, fmt.Errorf("httpproxy: invalid OnUnparsed %q (want %q or %q)", opts.OnUnparsed, UnparsedForward, UnparsedReject)
	}
	if opts.Logger == nil {
		opts.Logger = io.Discard
	}
	if opts.Client == nil {
		// No timeout: SSE responses are long-lived. Cancellation flows through
		// the request context instead.
		opts.Client = &http.Client{}
	}
	h := &Handler{opts: opts, client: opts.Client}
	if !opts.Passthrough {
		h.sess = opts.Engine.NewSession()
	}
	return h, nil
}

// Serve runs an HTTP server bound to listenAddr until ctx is cancelled, then
// shuts it down gracefully.
func Serve(ctx context.Context, listenAddr string, opts Options) error {
	h, err := NewHandler(opts)
	if err != nil {
		return err
	}
	srv := &http.Server{Addr: listenAddr, Handler: h}

	errCh := make(chan error, 1)
	go func() { errCh <- srv.ListenAndServe() }()

	fmt.Fprintf(h.opts.Logger, "httpproxy: listening on %s, forwarding to %s\n", listenAddr, opts.Upstream)

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return srv.Shutdown(shutdownCtx)
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h.opts.Debug {
		fmt.Fprintf(h.opts.Logger, "httpproxy: %s %s\n", r.Method, r.URL.Path)
	}

	// Authenticate first when a token is configured, so an unauthenticated
	// client can reach neither the policy edge nor the upstream server.
	if h.opts.AuthToken != "" && !h.authorized(r) {
		fmt.Fprintf(h.opts.Logger, "httpproxy: rejected unauthenticated %s %s\n", r.Method, r.URL.Path)
		w.Header().Set("WWW-Authenticate", "Bearer")
		http.Error(w, "httpproxy: missing or invalid bearer token", http.StatusUnauthorized)
		return
	}

	// Passthrough or anything that is not a POST cannot carry a tools/call we
	// gate; forward it transparently with its body intact.
	if h.opts.Passthrough || r.Method != http.MethodPost {
		h.forward(w, r, nil, "", nil, false)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, maxBodyBytes+1))
	if err != nil {
		fmt.Fprintln(h.opts.Logger, "httpproxy: read request body:", err)
		h.writeJSONRPC(w, mcp.ProxyError(nil, "error reading request body"))
		return
	}
	if len(body) > maxBodyBytes {
		// Oversize bodies are refused, never forwarded uninspected. Answer with
		// a JSON-RPC error envelope when the body looked like JSON-RPC so the
		// agent sees a structured error; otherwise a plain HTTP 413.
		fmt.Fprintln(h.opts.Logger, "httpproxy: rejecting oversize request body")
		if mcp.LooksLikeJSONRPC(body) {
			h.writeJSONRPC(w, mcp.RequestRejectedError(nil, "request body exceeds limit"))
		} else {
			http.Error(w, "httpproxy: request body exceeds limit", http.StatusRequestEntityTooLarge)
		}
		return
	}

	// A JSON-RPC batch (array) body bypasses the single-request parser, so
	// handle it explicitly per the configured policy instead of forwarding it
	// ungated (which could smuggle a denied tools/call inside the array).
	if mcp.IsBatch(body) {
		h.handleBatch(w, r, body)
		return
	}

	req, perr := mcp.ParseRequest(body)
	if perr != nil {
		// Unparseable as JSON-RPC: forward transparently, or refuse if the
		// operator opted into a fail-closed boundary.
		if h.opts.OnUnparsed == UnparsedReject {
			fmt.Fprintln(h.opts.Logger, "httpproxy: rejecting unparseable body:", perr)
			if mcp.LooksLikeJSONRPC(body) {
				h.writeJSONRPC(w, mcp.RequestRejectedError(nil, "request body is not valid JSON-RPC"))
			} else {
				http.Error(w, "httpproxy: request body is not valid JSON-RPC", http.StatusBadRequest)
			}
			return
		}
		// Unparseable, non-JSON-RPC body forwarded transparently: an upstream
		// failure stays a plain HTTP error, not a JSON-RPC envelope.
		h.forward(w, r, body, "", nil, false)
		return
	}
	if req.Method != mcp.MethodToolsCall {
		// Recognized JSON-RPC but not a gateable tools/call (initialize, ping,
		// notifications). Forward transparently so the session keeps working.
		h.forward(w, r, body, "", req.ID, true)
		return
	}

	params, perr := mcp.ParseToolCallParams(req.Params)
	if perr != nil {
		h.writeJSONRPC(w, mcp.InvalidParamsError(req.ID, perr.Error()))
		return
	}

	fallback := fmt.Sprintf("call-%d", atomic.AddUint64(&h.callCounter, 1))
	callID := mcp.CallIDFromRequestID(req.ID, fallback)
	call := params.ToToolCall(callID)
	result, event := h.sess.Evaluate(call)

	// Resolve an ask decision to a final allow/deny via the approver before we
	// audit, so the audit event records the outcome the agent actually saw
	// (mirrors the stdio proxy and the check command).
	if result.Decision == policy.DecisionAsk {
		outcome, aerr := approval.Resolve(r.Context(), h.opts.Approver, call, h.opts.ApprovalTimeout, h.opts.NoInteractive)
		if outcome.Approved {
			result.Decision = policy.DecisionAllow
		} else {
			result.Decision = policy.DecisionDeny
		}
		// Preserve the engine's reason for *why* the call was ask (e.g. a taint
		// escalation) and annotate it with the approval outcome, so the audit
		// trail keeps both the cause and how it was resolved.
		result.Reason = result.Reason + " (" + outcome.Reason + ")"
		event.Decision = result.Decision
		event.Reason = result.Reason
		if outcome.Reason == approval.ReasonApprovalIOError {
			// Surface the I/O detail to the operator only; the agent sees the
			// canonical reason, not the internal error text.
			fmt.Fprintf(h.opts.Logger, "httpproxy: approval I/O error for [%s] %s: %v\n", call.ID, call.Tool, aerr)
		}
	}

	// Audit so the decision is durable even if forwarding fails.
	if werr := h.opts.AuditWriter.Write(event); werr != nil {
		fmt.Fprintln(h.opts.Logger, "httpproxy: audit write:", werr)
	}

	switch result.Decision {
	case policy.DecisionAllow:
		h.forward(w, r, body, call.Tool, req.ID, true)
	case policy.DecisionDeny:
		h.writeJSONRPC(w, mcp.BlockedByPolicyError(req.ID, result.Reason))
	default:
		// Unknown decision: default-deny so a future decision value cannot
		// silently widen the allow set.
		h.writeJSONRPC(w, mcp.BlockedByPolicyError(req.ID, "unknown decision: "+string(result.Decision)))
	}
}

// authorized reports whether r carries the configured bearer token. The token
// is compared in constant time so the proxy does not leak it via timing.
func (h *Handler) authorized(r *http.Request) bool {
	const prefix = "Bearer "
	got := r.Header.Get("Authorization")
	if !strings.HasPrefix(got, prefix) {
		return false
	}
	token := strings.TrimSpace(got[len(prefix):])
	return subtle.ConstantTimeCompare([]byte(token), []byte(h.opts.AuthToken)) == 1
}

// handleBatch applies the configured BatchPolicy to a JSON-RPC batch body.
func (h *Handler) handleBatch(w http.ResponseWriter, r *http.Request, body []byte) {
	if h.opts.OnBatch == BatchReject {
		fmt.Fprintln(h.opts.Logger, "httpproxy: rejecting ungated JSON-RPC batch body")
		h.writeJSONRPC(w, mcp.BatchNotGatedError(nil, "send one request per body, or run with --on-batch evaluate"))
		return
	}

	// BatchEvaluate: evaluate every tools/call member and forward the whole
	// batch only if all members are allowed (all-or-nothing), so a denied
	// member can never ride along with allowed ones.
	reqs, err := mcp.ParseBatch(body)
	if err != nil {
		h.writeJSONRPC(w, mcp.RequestRejectedError(nil, "invalid JSON-RPC batch: "+err.Error()))
		return
	}
	for _, req := range reqs {
		if req.Method != mcp.MethodToolsCall {
			continue
		}
		params, perr := mcp.ParseToolCallParams(req.Params)
		if perr != nil {
			h.writeJSONRPC(w, mcp.InvalidParamsError(req.ID, perr.Error()))
			return
		}
		fallback := fmt.Sprintf("call-%d", atomic.AddUint64(&h.callCounter, 1))
		call := params.ToToolCall(mcp.CallIDFromRequestID(req.ID, fallback))
		result, event := h.sess.Evaluate(call)
		if werr := h.opts.AuditWriter.Write(event); werr != nil {
			fmt.Fprintln(h.opts.Logger, "httpproxy: audit write:", werr)
		}
		if result.Decision == policy.DecisionAllow {
			continue
		}
		if result.Decision == policy.DecisionAsk {
			if approved, aerr := h.opts.Approver.Request(r.Context(), call); aerr == nil && approved {
				continue
			}
		}
		// Any non-allow member fails the whole batch.
		h.writeJSONRPC(w, mcp.BlockedByPolicyError(nil,
			fmt.Sprintf("batch rejected: tools/call %q -> %s: %s", call.Tool, result.Decision, result.Reason)))
		return
	}
	// All members allowed: forward the batch unchanged. Batch responses are not
	// split for per-member taint observation, so no observeTool is attributed.
	// A batch is JSON-RPC, so an upstream failure is returned as an envelope.
	h.forward(w, r, body, "", nil, true)
}

// forward proxies r to the upstream MCP server and relays the response. When
// body is non-nil it is used as the request body (already buffered for
// inspection); otherwise r.Body is streamed. observeTool, when set, attributes
// the response to a tool for taint observation. id is the originating JSON-RPC
// request id (or nil) used to address a failure back to the agent distinctly
// from a policy block. jsonRPC reports whether the request is JSON-RPC: when
// true a failure is returned as a JSON-RPC error envelope (HTTP 200), otherwise
// it is a plain HTTP 502 so non-JSON-RPC clients (SSE GET, passthrough, and
// transparently-forwarded bodies) keep the HTTP contract they expect. Failure
// detail is logged operator-side; the agent-facing message never echoes the
// upstream URL or dial address.
func (h *Handler) forward(w http.ResponseWriter, r *http.Request, body []byte, observeTool string, id json.RawMessage, jsonRPC bool) {
	target := h.targetURL(r)

	var reqBody io.Reader
	if body != nil {
		reqBody = bytes.NewReader(body)
	} else {
		reqBody = r.Body
	}

	outReq, err := http.NewRequestWithContext(r.Context(), r.Method, target, reqBody)
	if err != nil {
		fmt.Fprintln(h.opts.Logger, "httpproxy: build upstream request:", err)
		if jsonRPC {
			h.writeJSONRPC(w, mcp.ProxyError(id, "could not build upstream request"))
		} else {
			http.Error(w, "httpproxy: could not build upstream request", http.StatusBadGateway)
		}
		return
	}
	copyHeader(outReq.Header, r.Header)
	removeHopByHopHeaders(outReq.Header)
	outReq.Header.Del("Host")
	// When the proxy enforces its own bearer token, that header is the client's
	// credential to AgentFence, not to the upstream; strip it so the gate token
	// is never relayed onward. Without proxy auth, preserve the client's
	// Authorization header so upstreams that authenticate the client still work.
	if h.opts.AuthToken != "" {
		outReq.Header.Del("Authorization")
	}
	// Drop the client's Accept-Encoding so Go's transport sets and transparently
	// decompresses its own encoding; otherwise observeResponse() would see
	// compressed bytes it cannot parse as JSON for taint observation.
	outReq.Header.Del("Accept-Encoding")
	if body != nil {
		outReq.ContentLength = int64(len(body))
	}

	resp, err := h.client.Do(outReq)
	if err != nil {
		fmt.Fprintln(h.opts.Logger, "httpproxy: upstream request failed:", err)
		if jsonRPC {
			h.writeJSONRPC(w, mcp.UpstreamError(id, sanitizedUpstreamReason(err)))
		} else {
			http.Error(w, "httpproxy: upstream MCP server unavailable", http.StatusBadGateway)
		}
		return
	}
	defer resp.Body.Close()

	// Record the upstream content type before relaying so observation can pick
	// the right parser (plain JSON vs. SSE framing) once the body is captured.
	contentType := resp.Header.Get("Content-Type")

	copyHeader(w.Header(), resp.Header)
	removeHopByHopHeaders(w.Header())
	w.WriteHeader(resp.StatusCode)

	// Capture (capped) the body of an allowed tool's response for taint
	// observation while still streaming it to the client.
	var capture *cappedBuffer
	src := io.Reader(resp.Body)
	if observeTool != "" && h.sess != nil && h.sess.TaintEnabled() {
		capture = &cappedBuffer{limit: maxObserveBytes}
		src = io.TeeReader(resp.Body, capture)
	}

	flushCopy(w, src)

	if capture != nil {
		h.observeResponse(observeTool, contentType, capture.Bytes())
	}
}

// sanitizedUpstreamReason returns a short description of an upstream request
// failure for the agent-facing JSON-RPC error envelope. It deliberately does
// not echo the upstream URL or dial address (Go wraps those in *url.Error /
// *net.OpError); the full error is logged operator-side instead.
func sanitizedUpstreamReason(err error) string {
	switch {
	case errors.Is(err, context.Canceled):
		return "request canceled"
	case errors.Is(err, context.DeadlineExceeded):
		return "request timed out"
	default:
		return "the upstream server could not be reached"
	}
}

// observeResponse extracts a tools/call result from an upstream response body
// and feeds its text to the taint tracker. A text/event-stream (SSE) body is
// reassembled from its data: frames; any other body is parsed as a single
// JSON-RPC response. Bodies that yield no parseable result are ignored.
func (h *Handler) observeResponse(tool, contentType string, body []byte) {
	if isEventStream(contentType) {
		for _, payload := range sseDataPayloads(body) {
			h.observeJSONResponse(tool, payload)
		}
		return
	}
	h.observeJSONResponse(tool, body)
}

// observeJSONResponse parses a single JSON-RPC response payload and feeds its
// tools/call result text to the taint tracker.
func (h *Handler) observeJSONResponse(tool string, payload []byte) {
	resp, err := mcp.ParseResponse(payload)
	if err != nil || len(resp.Result) == 0 {
		return
	}
	if text := mcp.ResultText(resp.Result); text != "" {
		h.sess.ObserveResult(tool, text)
	}
}

// isEventStream reports whether a Content-Type names the SSE media type,
// ignoring parameters such as a charset (e.g. "text/event-stream; charset=utf-8").
func isEventStream(contentType string) bool {
	if contentType == "" {
		return false
	}
	if mt, _, err := mime.ParseMediaType(contentType); err == nil {
		return mt == "text/event-stream"
	}
	// Best-effort fallback: a malformed but still recognizable Content-Type
	// (e.g. an invalid parameter after the media type) must not silently
	// disable SSE observation and reintroduce the taint-tracking gap this
	// guards against. Compare the bare type token before any ';'.
	base, _, _ := strings.Cut(contentType, ";")
	return strings.EqualFold(strings.TrimSpace(base), "text/event-stream")
}

// sseDataPayloads reassembles the data field of each SSE event in body. Per the
// EventSource framing, an event is terminated by a blank line and its data is
// the concatenation of its "data:" lines joined by newlines (a single optional
// leading space after the colon is stripped). Comment lines and other fields
// (event:, id:, retry:) are ignored. body is already capped at maxObserveBytes
// by the caller.
func sseDataPayloads(body []byte) [][]byte {
	var payloads [][]byte
	var cur []string
	flush := func() {
		if len(cur) > 0 {
			payloads = append(payloads, []byte(strings.Join(cur, "\n")))
			cur = nil
		}
	}

	sc := bufio.NewScanner(bytes.NewReader(body))
	// A single data line may approach the capture cap, so size the scanner's
	// token buffer accordingly rather than relying on the 64 KiB default.
	sc.Buffer(make([]byte, 0, 64*1024), maxObserveBytes+1)
	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), "\r")
		if line == "" {
			flush()
			continue
		}
		if data, ok := strings.CutPrefix(line, "data:"); ok {
			cur = append(cur, strings.TrimPrefix(data, " "))
		}
	}
	if sc.Err() != nil {
		// A scan error (e.g. a single frame exceeding the buffer) leaves cur
		// holding a truncated, unterminated frame. Drop it rather than observe a
		// partial payload: already-flushed frames remain valid, but the in-flight
		// one must not be fed to the taint tracker as if it were complete.
		return payloads
	}
	flush()
	return payloads
}

// targetURL composes the upstream URL: the upstream base joined with the
// incoming request path and query.
func (h *Handler) targetURL(r *http.Request) string {
	u := *h.opts.Upstream
	u.Path = singleJoiningSlash(h.opts.Upstream.Path, r.URL.Path)
	u.RawQuery = r.URL.RawQuery
	return u.String()
}

func (h *Handler) writeJSONRPC(w http.ResponseWriter, resp mcp.JSONRPCResponse) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := writeJSON(w, resp); err != nil {
		fmt.Fprintln(h.opts.Logger, "httpproxy: write response:", err)
	}
}

// flushCopy streams src to w, flushing after each chunk so streamed responses
// (text/event-stream) reach the client incrementally instead of being buffered.
func flushCopy(w http.ResponseWriter, src io.Reader) {
	flusher, _ := w.(http.Flusher)
	buf := make([]byte, 32*1024)
	for {
		n, err := src.Read(buf)
		if n > 0 {
			if _, werr := w.Write(buf[:n]); werr != nil {
				return
			}
			if flusher != nil {
				flusher.Flush()
			}
		}
		if err != nil {
			return
		}
	}
}

func writeJSON(w io.Writer, v interface{}) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	_, err = w.Write(append(b, '\n'))
	return err
}

func copyHeader(dst, src http.Header) {
	for k, vs := range src {
		for _, v := range vs {
			dst.Add(k, v)
		}
	}
}

// hopByHopHeaders are connection-specific headers a proxy must not forward
// (RFC 7230 §6.1). Transfer-Encoding and Content-Length are managed by Go's
// HTTP stack itself.
var hopByHopHeaders = []string{
	"Connection",
	"Proxy-Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Te",
	"Trailer",
	"Transfer-Encoding",
	"Upgrade",
}

// removeHopByHopHeaders strips connection-specific headers (RFC 7230 §6.1) from
// h, including any named in the Connection header, so they are not forwarded
// across the proxy boundary.
func removeHopByHopHeaders(h http.Header) {
	for _, f := range h["Connection"] {
		for _, sf := range strings.Split(f, ",") {
			if name := strings.TrimSpace(sf); name != "" {
				h.Del(name)
			}
		}
	}
	for _, k := range hopByHopHeaders {
		h.Del(k)
	}
}

func singleJoiningSlash(a, b string) string {
	aslash := strings.HasSuffix(a, "/")
	bslash := strings.HasPrefix(b, "/")
	switch {
	case aslash && bslash:
		return a + b[1:]
	case !aslash && !bslash && b != "":
		return a + "/" + b
	}
	return a + b
}

// cappedBuffer accumulates up to limit bytes and silently discards the rest, so
// taint capture cannot grow unbounded on a large or streamed response.
type cappedBuffer struct {
	buf   bytes.Buffer
	limit int
}

func (c *cappedBuffer) Write(p []byte) (int, error) {
	if remaining := c.limit - c.buf.Len(); remaining > 0 {
		if len(p) > remaining {
			c.buf.Write(p[:remaining])
		} else {
			c.buf.Write(p)
		}
	}
	// Report the full length so the TeeReader does not error.
	return len(p), nil
}

func (c *cappedBuffer) Bytes() []byte { return c.buf.Bytes() }
