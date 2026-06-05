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
// Because JSON-RPC carries errors in a 200 response envelope, a policy denial
// is returned as HTTP 200 with a JSON-RPC error body, not an HTTP error status.
// See docs/threat-model.md for the HTTP-specific surface (auth, TLS, and
// multi-client session handling) that the stdio transport does not have.
package httpproxy

import (
	"bufio"
	"bytes"
	"context"
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
// runtime. It mirrors proxy.Approver; the HTTP proxy keeps its own one-method
// interface to avoid coupling the two transports.
type Approver interface {
	Request(ctx context.Context, call policy.ToolCall) (bool, error)
}

// DenyAllApprover converts every ask decision into deny. Use this in
// non-interactive contexts (CI, --no-interactive).
type DenyAllApprover struct{}

// Request always returns (false, nil) — an unattended proxy must default-deny.
func (DenyAllApprover) Request(context.Context, policy.ToolCall) (bool, error) {
	return false, nil
}

// Options configures NewHandler. Engine, AuditWriter, and Upstream are required
// unless Passthrough is true.
type Options struct {
	// Engine evaluates each intercepted tools/call. Required unless Passthrough.
	Engine *engine.Engine
	// AuditWriter records evaluation decisions. Required unless Passthrough.
	AuditWriter *audit.Writer
	// Approver handles ask decisions. Defaults to DenyAllApprover.
	Approver Approver
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

	// Passthrough or anything that is not a POST cannot carry a tools/call we
	// gate; forward it transparently with its body intact.
	if h.opts.Passthrough || r.Method != http.MethodPost {
		h.forward(w, r, nil, "")
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, maxBodyBytes+1))
	if err != nil {
		http.Error(w, "httpproxy: error reading request body", http.StatusBadGateway)
		return
	}
	if len(body) > maxBodyBytes {
		http.Error(w, "httpproxy: request body exceeds limit", http.StatusRequestEntityTooLarge)
		return
	}

	req, perr := mcp.ParseRequest(body)
	if perr != nil || req.Method != mcp.MethodToolsCall {
		// Not a gateable tools/call — forward transparently with the buffered body.
		h.forward(w, r, body, "")
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

	// Audit first so the decision is durable even if forwarding fails.
	if werr := h.opts.AuditWriter.Write(event); werr != nil {
		fmt.Fprintln(h.opts.Logger, "httpproxy: audit write:", werr)
	}

	switch result.Decision {
	case policy.DecisionAllow:
		h.forward(w, r, body, call.Tool)
	case policy.DecisionDeny:
		h.writeJSONRPC(w, mcp.BlockedByPolicyError(req.ID, result.Reason))
	case policy.DecisionAsk:
		approved, aerr := h.opts.Approver.Request(r.Context(), call)
		switch {
		case aerr != nil:
			h.writeJSONRPC(w, mcp.BlockedByPolicyError(req.ID, "approval error: "+aerr.Error()))
		case approved:
			h.forward(w, r, body, call.Tool)
		default:
			h.writeJSONRPC(w, mcp.BlockedByPolicyError(req.ID, result.Reason+" (denied via ask)"))
		}
	default:
		// Unknown decision: default-deny so a future decision value cannot
		// silently widen the allow set.
		h.writeJSONRPC(w, mcp.BlockedByPolicyError(req.ID, "unknown decision: "+string(result.Decision)))
	}
}

// forward proxies r to the upstream MCP server and relays the response. When
// body is non-nil it is used as the request body (already buffered for
// inspection); otherwise r.Body is streamed. observeTool, when set, attributes
// the response to a tool for taint observation.
func (h *Handler) forward(w http.ResponseWriter, r *http.Request, body []byte, observeTool string) {
	target := h.targetURL(r)

	var reqBody io.Reader
	if body != nil {
		reqBody = bytes.NewReader(body)
	} else {
		reqBody = r.Body
	}

	outReq, err := http.NewRequestWithContext(r.Context(), r.Method, target, reqBody)
	if err != nil {
		http.Error(w, "httpproxy: build upstream request: "+err.Error(), http.StatusBadGateway)
		return
	}
	copyHeader(outReq.Header, r.Header)
	removeHopByHopHeaders(outReq.Header)
	outReq.Header.Del("Host")
	// Drop the client's Accept-Encoding so Go's transport sets and transparently
	// decompresses its own encoding; otherwise observeResponse() would see
	// compressed bytes it cannot parse as JSON for taint observation.
	outReq.Header.Del("Accept-Encoding")
	if body != nil {
		outReq.ContentLength = int64(len(body))
	}

	resp, err := h.client.Do(outReq)
	if err != nil {
		http.Error(w, "httpproxy: upstream request failed: "+err.Error(), http.StatusBadGateway)
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
	mt, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		return false
	}
	return mt == "text/event-stream"
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
