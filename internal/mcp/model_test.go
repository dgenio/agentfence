package mcp

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestParseRequestValid(t *testing.T) {
	raw := []byte(`{"jsonrpc":"2.0","id":42,"method":"tools/call","params":{"name":"filesystem.read","arguments":{"path":"README.md"}}}`)
	req, err := ParseRequest(raw)
	if err != nil {
		t.Fatalf("ParseRequest: %v", err)
	}
	if req.JSONRPC != JSONRPCVersion {
		t.Errorf("jsonrpc = %q, want %q", req.JSONRPC, JSONRPCVersion)
	}
	if req.Method != MethodToolsCall {
		t.Errorf("method = %q, want %q", req.Method, MethodToolsCall)
	}
	if string(req.ID) != "42" {
		t.Errorf("id raw = %q, want %q", string(req.ID), "42")
	}
}

func TestParseRequestMalformed(t *testing.T) {
	if _, err := ParseRequest([]byte("not json")); err == nil {
		t.Fatal("expected error parsing non-JSON")
	}
}

func TestParseToolCallParamsValid(t *testing.T) {
	raw := json.RawMessage(`{"name":"filesystem.write","arguments":{"path":".env","content":"x"}}`)
	p, err := ParseToolCallParams(raw)
	if err != nil {
		t.Fatalf("ParseToolCallParams: %v", err)
	}
	if p.Name != "filesystem.write" {
		t.Errorf("name = %q, want filesystem.write", p.Name)
	}
	if p.Arguments["path"] != ".env" {
		t.Errorf("arguments[path] = %v, want .env", p.Arguments["path"])
	}
}

func TestParseToolCallParamsErrors(t *testing.T) {
	cases := []struct {
		name string
		raw  json.RawMessage
	}{
		{"empty", json.RawMessage(``)},
		{"missing-name", json.RawMessage(`{"arguments":{}}`)},
		{"non-object", json.RawMessage(`42`)},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParseToolCallParams(tc.raw); err == nil {
				t.Fatalf("expected error for %s, got nil", tc.name)
			}
		})
	}
}

func TestToToolCallNilArguments(t *testing.T) {
	p := ToolCallParams{Name: "shell.exec"}
	call := p.ToToolCall("c-1")
	if call.ID != "c-1" || call.Tool != "shell.exec" {
		t.Errorf("unexpected call: %+v", call)
	}
	if call.Arguments == nil {
		t.Error("Arguments must not be nil after ToToolCall (engine relies on this)")
	}
	if len(call.Arguments) != 0 {
		t.Errorf("Arguments = %v, want empty map", call.Arguments)
	}
}

func TestToToolCallWithArguments(t *testing.T) {
	p := ToolCallParams{
		Name:      "filesystem.read",
		Arguments: map[string]interface{}{"path": "README.md"},
	}
	call := p.ToToolCall("c-2")
	if call.Arguments["path"] != "README.md" {
		t.Errorf("Arguments[path] = %v, want README.md", call.Arguments["path"])
	}
}

func TestBlockedByPolicyError(t *testing.T) {
	resp := BlockedByPolicyError(json.RawMessage(`"abc"`), "denied because reasons")
	if resp.JSONRPC != JSONRPCVersion {
		t.Errorf("jsonrpc = %q, want %q", resp.JSONRPC, JSONRPCVersion)
	}
	if string(resp.ID) != `"abc"` {
		t.Errorf("id = %s, want \"abc\"", string(resp.ID))
	}
	if resp.Error == nil {
		t.Fatal("Error must be non-nil for a blocked response")
	}
	if resp.Result != nil {
		t.Errorf("Result must be nil on an error response, got %s", string(resp.Result))
	}
	if resp.Error.Code != ErrorCodeBlockedByPolicy {
		t.Errorf("code = %d, want %d", resp.Error.Code, ErrorCodeBlockedByPolicy)
	}
	if !strings.Contains(resp.Error.Message, "denied because reasons") {
		t.Errorf("message %q must contain the reason", resp.Error.Message)
	}

	// Round-trip: a real proxy serialises the response on the wire; verify
	// the JSON shape matches the JSON-RPC spec (jsonrpc, id, error.{code,message}).
	b, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	want := `{"jsonrpc":"2.0","id":"abc","error":{"code":-32001,"message":"blocked by AgentFence policy: denied because reasons"}}`
	if string(b) != want {
		t.Errorf("marshalled = %s\nwant         = %s", b, want)
	}
}

func TestInvalidParamsError(t *testing.T) {
	resp := InvalidParamsError(json.RawMessage(`7`), "missing name")
	if resp.Error == nil || resp.Error.Code != ErrorCodeInvalidParams {
		t.Errorf("code = %v, want %d", resp.Error, ErrorCodeInvalidParams)
	}
	if !strings.Contains(resp.Error.Message, "missing name") {
		t.Errorf("message must contain reason, got %q", resp.Error.Message)
	}
}

func TestErrorCodesAreSpecCompliant(t *testing.T) {
	// JSON-RPC 2.0 reserves -32099..-32000 for implementation-defined server
	// errors. AgentFence-specific codes must fall in that range so they
	// can be distinguished from spec codes.
	if ErrorCodeBlockedByPolicy < -32099 || ErrorCodeBlockedByPolicy > -32000 {
		t.Errorf("ErrorCodeBlockedByPolicy %d outside JSON-RPC server-error range",
			ErrorCodeBlockedByPolicy)
	}
}

func TestCallIDFromRequestID(t *testing.T) {
	cases := []struct {
		name     string
		raw      string
		fallback string
		want     string
	}{
		{"string", `"abc-123"`, "fb", "abc-123"},
		{"integer", `42`, "fb", "42"},
		{"float", `1.5`, "fb", "1.5"},
		// JSON allows integers larger than 2^53; we must not silently
		// truncate them by going through float64. Use the exact on-wire
		// bytes instead.
		{"large-integer", `9007199254740993`, "fb", "9007199254740993"},
		{"null", `null`, "fb", "fb"},
		{"empty", ``, "fb", "fb"},
		{"whitespace-only", `   `, "fb", "fb"},
		{"whitespace-padded-number", `  7  `, "fb", "7"},
		{"object", `{"k":1}`, "fb", `{"k":1}`},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			var raw json.RawMessage
			if tc.raw != "" {
				raw = json.RawMessage(tc.raw)
			}
			got := CallIDFromRequestID(raw, tc.fallback)
			if got != tc.want {
				t.Errorf("CallIDFromRequestID(%q) = %q, want %q", tc.raw, got, tc.want)
			}
		})
	}
}

func TestJSONRPCResponseSerialization(t *testing.T) {
	// Verify a successful response can be constructed and round-tripped.
	resultRaw := json.RawMessage(`{"content":[{"type":"text","text":"ok"}]}`)
	resp := JSONRPCResponse{
		JSONRPC: JSONRPCVersion,
		ID:      json.RawMessage(`1`),
		Result:  resultRaw,
	}
	b, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var round JSONRPCResponse
	if err := json.Unmarshal(b, &round); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if round.Error != nil {
		t.Errorf("Error must remain nil on success path, got %+v", round.Error)
	}
}

func TestParseToolCallParamsErrorIsWrapped(t *testing.T) {
	// fmt.Errorf("...: %w", err) means errors.Unwrap returns the underlying
	// json error. This lets callers do errors.Is checks if they care.
	_, err := ParseToolCallParams(json.RawMessage(`not json`))
	if err == nil {
		t.Fatal("expected error")
	}
	if errors.Unwrap(err) == nil {
		t.Error("expected wrapped error from ParseToolCallParams on malformed JSON")
	}
}

func TestIsBatch(t *testing.T) {
	cases := []struct {
		name string
		body string
		want bool
	}{
		{"array", `[{"jsonrpc":"2.0"}]`, true},
		{"array leading ws", "  \n\t[1,2]", true},
		{"object", `{"jsonrpc":"2.0"}`, false},
		{"empty", "", false},
		{"garbage", "not json", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsBatch([]byte(tc.body)); got != tc.want {
				t.Errorf("IsBatch(%q) = %v, want %v", tc.body, got, tc.want)
			}
		})
	}
}

func TestLooksLikeJSONRPC(t *testing.T) {
	cases := []struct {
		body string
		want bool
	}{
		{`{"a":1}`, true},
		{"  [1]", true},
		{"plain text", false},
		{"", false},
	}
	for _, tc := range cases {
		if got := LooksLikeJSONRPC([]byte(tc.body)); got != tc.want {
			t.Errorf("LooksLikeJSONRPC(%q) = %v, want %v", tc.body, got, tc.want)
		}
	}
}

func TestParseBatch(t *testing.T) {
	reqs, err := ParseBatch([]byte(`[{"jsonrpc":"2.0","id":1,"method":"tools/call"},{"jsonrpc":"2.0","id":2,"method":"ping"}]`))
	if err != nil {
		t.Fatalf("ParseBatch: %v", err)
	}
	if len(reqs) != 2 {
		t.Fatalf("got %d requests, want 2", len(reqs))
	}
	if reqs[0].Method != "tools/call" || reqs[1].Method != "ping" {
		t.Errorf("unexpected methods: %q, %q", reqs[0].Method, reqs[1].Method)
	}
	if _, err := ParseBatch([]byte(`{"not":"an array"}`)); err == nil {
		t.Error("ParseBatch must error on a non-array body")
	}
}

func TestProxyErrorCodes(t *testing.T) {
	id := json.RawMessage(`5`)
	cases := []struct {
		name string
		resp JSONRPCResponse
		code int
	}{
		{"upstream", UpstreamError(id, "refused"), ErrorCodeUpstreamUnavailable},
		{"proxy", ProxyError(id, "read"), ErrorCodeProxyError},
		{"batch", BatchNotGatedError(nil, "no"), ErrorCodeBatchNotGated},
		{"rejected", RequestRejectedError(nil, "oversize"), ErrorCodeRequestRejected},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.resp.Error == nil {
				t.Fatalf("%s: Error must be set", tc.name)
			}
			if tc.resp.Error.Code != tc.code {
				t.Errorf("%s: code = %d, want %d", tc.name, tc.resp.Error.Code, tc.code)
			}
			if tc.resp.JSONRPC != JSONRPCVersion {
				t.Errorf("%s: jsonrpc = %q", tc.name, tc.resp.JSONRPC)
			}
		})
	}
}
