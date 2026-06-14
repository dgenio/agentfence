// Package mcp defines the AgentFence-internal Model Context Protocol (MCP)
// message types used by the stdio proxy.
//
// AgentFence only models the subset of MCP it needs to gate tool calls:
// JSON-RPC 2.0 request/response envelopes, the tools/call params and result
// shapes, and the JSON-RPC error response used to block a denied call. Server
// capability negotiation, SSE framing, and the rest of the MCP 1.0 surface are
// intentionally out of scope.
package mcp

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/dgenio/agentfence/internal/policy"
)

// Standard JSON-RPC 2.0 error codes (https://www.jsonrpc.org/specification).
const (
	ErrorCodeParseError     = -32700
	ErrorCodeInvalidRequest = -32600
	ErrorCodeMethodNotFound = -32601
	ErrorCodeInvalidParams  = -32602
	ErrorCodeInternalError  = -32603
)

// AgentFence-specific error codes occupy the JSON-RPC implementation-defined
// server-error range (-32000 to -32099, per the spec).
const (
	// ErrorCodeBlockedByPolicy is returned to the agent when the policy
	// denies a tools/call request (either directly or after an ask
	// decision is converted to a deny by the approver).
	ErrorCodeBlockedByPolicy = -32001
	// ErrorCodeUpstreamUnavailable is returned when the proxy cannot reach or
	// complete a request to the upstream MCP server (connection refused,
	// network failure). It lets the agent and operator tell a transport
	// failure apart from a policy block.
	ErrorCodeUpstreamUnavailable = -32002
	// ErrorCodeProxyError is returned for an internal proxy failure (e.g. the
	// proxy could not read or build a request) that is neither a policy block
	// nor an upstream failure.
	ErrorCodeProxyError = -32003
	// ErrorCodeBatchNotGated is returned when a JSON-RPC batch (array) body is
	// refused because the proxy is configured not to gate batches.
	ErrorCodeBatchNotGated = -32004
	// ErrorCodeRequestRejected is returned when the proxy refuses a request
	// body up front (oversize, or unparseable under a reject policy) instead of
	// forwarding it uninspected and bypassing the gate.
	ErrorCodeRequestRejected = -32005
)

// JSONRPCVersion is the only JSON-RPC version AgentFence speaks.
const JSONRPCVersion = "2.0"

// MethodToolsCall is the MCP method name used to invoke a tool.
const MethodToolsCall = "tools/call"

// JSONRPCRequest is a JSON-RPC 2.0 request envelope.
//
// ID is held as RawMessage because JSON-RPC allows strings, numbers, or null.
// Params is held as RawMessage so unknown methods can be forwarded untouched
// and only tools/call needs the typed ToolCallParams shape.
type JSONRPCRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

// JSONRPCResponse is a JSON-RPC 2.0 response envelope. Exactly one of Result
// or Error is set on a valid response.
type JSONRPCResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *JSONRPCError   `json:"error,omitempty"`
}

// JSONRPCError is the error object inside a JSONRPCResponse.
type JSONRPCError struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data,omitempty"`
}

// ToolCallParams is the params shape for an MCP tools/call request.
type ToolCallParams struct {
	Name      string                 `json:"name"`
	Arguments map[string]interface{} `json:"arguments,omitempty"`
}

// ToolCallResult is the result shape returned by an MCP server for a
// successful tools/call response. AgentFence does not currently inspect tool
// results; the type is defined for completeness so callers can build
// synthetic results if needed in tests.
type ToolCallResult struct {
	Content []ContentItem `json:"content"`
	IsError bool          `json:"isError,omitempty"`
}

// ContentItem is one entry in a ToolCallResult.Content array.
type ContentItem struct {
	Type string `json:"type"`
	Text string `json:"text,omitempty"`
}

// ParseRequest parses a single newline-delimited JSON-RPC request payload.
func ParseRequest(b []byte) (JSONRPCRequest, error) {
	var req JSONRPCRequest
	if err := json.Unmarshal(b, &req); err != nil {
		return JSONRPCRequest{}, fmt.Errorf("mcp: parse request: %w", err)
	}
	return req, nil
}

// IsBatch reports whether body is a JSON-RPC batch request: a payload whose
// first non-whitespace byte is '['. Per JSON-RPC 2.0 §6 a batch is an array of
// request objects, which the single-request parser does not model.
func IsBatch(body []byte) bool {
	for _, b := range body {
		switch b {
		case ' ', '\t', '\r', '\n':
			continue
		case '[':
			return true
		default:
			return false
		}
	}
	return false
}

// LooksLikeJSONRPC reports whether body begins (after leading whitespace) with
// '{' or '[', i.e. it is plausibly a JSON-RPC request or batch. Callers use it
// to decide whether to answer a refused body with a JSON-RPC error envelope or
// a plain HTTP error.
func LooksLikeJSONRPC(body []byte) bool {
	for _, b := range body {
		switch b {
		case ' ', '\t', '\r', '\n':
			continue
		case '{', '[':
			return true
		default:
			return false
		}
	}
	return false
}

// ParseBatch parses a JSON-RPC batch (array) body into its member requests.
func ParseBatch(b []byte) ([]JSONRPCRequest, error) {
	var reqs []JSONRPCRequest
	if err := json.Unmarshal(b, &reqs); err != nil {
		return nil, fmt.Errorf("mcp: parse batch: %w", err)
	}
	return reqs, nil
}

// ParseResponse parses a single newline-delimited JSON-RPC response payload.
func ParseResponse(b []byte) (JSONRPCResponse, error) {
	var resp JSONRPCResponse
	if err := json.Unmarshal(b, &resp); err != nil {
		return JSONRPCResponse{}, fmt.Errorf("mcp: parse response: %w", err)
	}
	return resp, nil
}

// ResultText extracts and concatenates the text content of a tools/call result.
// It returns an empty string when result is not a ToolCallResult or carries no
// text content. Used by the proxy to feed untrusted tool output into taint
// tracking; non-text content (images, structured blobs) is ignored.
func ResultText(result json.RawMessage) string {
	var r ToolCallResult
	if err := json.Unmarshal(result, &r); err != nil {
		return ""
	}
	var b strings.Builder
	for _, item := range r.Content {
		if item.Text == "" {
			continue
		}
		if b.Len() > 0 {
			b.WriteByte('\n')
		}
		b.WriteString(item.Text)
	}
	return b.String()
}

// ParseToolCallParams unmarshals the params field of a tools/call request.
// It returns an error when params is empty or when the required Name field
// is missing — both shapes are programming/protocol errors the proxy should
// surface as JSON-RPC InvalidParams instead of forwarding to the subprocess.
func ParseToolCallParams(params json.RawMessage) (ToolCallParams, error) {
	if len(params) == 0 {
		return ToolCallParams{}, errors.New("mcp: tools/call params are empty")
	}
	var p ToolCallParams
	if err := json.Unmarshal(params, &p); err != nil {
		return ToolCallParams{}, fmt.Errorf("mcp: parse tools/call params: %w", err)
	}
	if p.Name == "" {
		return ToolCallParams{}, errors.New("mcp: tools/call params missing name")
	}
	return p, nil
}

// ToToolCall converts MCP tools/call params + a request identifier into the
// AgentFence policy.ToolCall representation that the engine evaluates.
//
// callID should be derived from the JSON-RPC request ID by the caller (see
// proxy.CallIDFromRequestID); ToToolCall does not parse it.
func (p ToolCallParams) ToToolCall(callID string) policy.ToolCall {
	args := p.Arguments
	if args == nil {
		args = map[string]interface{}{}
	}
	return policy.ToolCall{
		ID:        callID,
		Tool:      p.Name,
		Arguments: args,
	}
}

// BlockedByPolicyError returns a JSON-RPC error response a proxy can write
// back to the agent in place of forwarding a denied tools/call request. The
// caller is responsible for serialising the response onto the agent's stdout
// stream.
func BlockedByPolicyError(id json.RawMessage, reason string) JSONRPCResponse {
	return JSONRPCResponse{
		JSONRPC: JSONRPCVersion,
		ID:      id,
		Error: &JSONRPCError{
			Code:    ErrorCodeBlockedByPolicy,
			Message: "blocked by AgentFence policy: " + reason,
		},
	}
}

// InvalidParamsError returns a JSON-RPC error response for a tools/call
// request whose params could not be parsed. AgentFence uses this when the
// agent sends a malformed tools/call — the proxy must answer with a
// well-formed error rather than forwarding garbage to the subprocess.
func InvalidParamsError(id json.RawMessage, reason string) JSONRPCResponse {
	return JSONRPCResponse{
		JSONRPC: JSONRPCVersion,
		ID:      id,
		Error: &JSONRPCError{
			Code:    ErrorCodeInvalidParams,
			Message: "invalid tools/call params: " + reason,
		},
	}
}

// UpstreamError returns a JSON-RPC error response for a request the proxy
// could not deliver to the upstream MCP server (connection refused, network
// failure). It is distinct from a policy block so an operator can tell a
// transport failure apart from an enforcement decision.
func UpstreamError(id json.RawMessage, reason string) JSONRPCResponse {
	return JSONRPCResponse{
		JSONRPC: JSONRPCVersion,
		ID:      id,
		Error: &JSONRPCError{
			Code:    ErrorCodeUpstreamUnavailable,
			Message: "upstream MCP server unavailable: " + reason,
		},
	}
}

// ProxyError returns a JSON-RPC error response for an internal proxy failure
// that is neither a policy block nor an upstream failure (e.g. the proxy could
// not read or build the request).
func ProxyError(id json.RawMessage, reason string) JSONRPCResponse {
	return JSONRPCResponse{
		JSONRPC: JSONRPCVersion,
		ID:      id,
		Error: &JSONRPCError{
			Code:    ErrorCodeProxyError,
			Message: "AgentFence proxy error: " + reason,
		},
	}
}

// BatchNotGatedError returns a JSON-RPC error response refusing a JSON-RPC
// batch (array) body the proxy is configured not to gate. id is typically null
// because the batch envelope itself carries no request id.
func BatchNotGatedError(id json.RawMessage, reason string) JSONRPCResponse {
	return JSONRPCResponse{
		JSONRPC: JSONRPCVersion,
		ID:      id,
		Error: &JSONRPCError{
			Code:    ErrorCodeBatchNotGated,
			Message: "JSON-RPC batch not gated by AgentFence: " + reason,
		},
	}
}

// RequestRejectedError returns a JSON-RPC error response for a body the proxy
// refused up front (oversize, or unparseable under a reject policy) rather than
// forwarding it uninspected.
func RequestRejectedError(id json.RawMessage, reason string) JSONRPCResponse {
	return JSONRPCResponse{
		JSONRPC: JSONRPCVersion,
		ID:      id,
		Error: &JSONRPCError{
			Code:    ErrorCodeRequestRejected,
			Message: "request rejected by AgentFence proxy: " + reason,
		},
	}
}

// CallIDFromRequestID derives a short, audit-friendly call identifier from a
// JSON-RPC request ID. Strings are unquoted; numbers and other shapes are
// rendered verbatim from their on-wire JSON bytes (with surrounding
// whitespace trimmed) so large integer IDs do not lose precision the way
// a float64 round-trip would. When the request has no ID (notification, or
// malformed), fallback is used so the audit event still has a non-empty
// CallID.
func CallIDFromRequestID(id json.RawMessage, fallback string) string {
	trimmed := bytes.TrimSpace(id)
	if len(trimmed) == 0 || string(trimmed) == "null" {
		return fallback
	}
	// Try a JSON string first (the common case for MCP clients).
	var s string
	if err := json.Unmarshal(trimmed, &s); err == nil && s != "" {
		return s
	}
	// For numbers, objects, arrays, booleans: return the raw JSON bytes.
	// This preserves full precision for large integers (>2^53) which would
	// be silently rounded by decoding through float64.
	return string(trimmed)
}
