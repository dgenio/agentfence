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
