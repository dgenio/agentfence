package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/dgenio/agentfence/internal/mcp"
)

// decodeResponses parses every newline-delimited JSON-RPC response the stub
// wrote to out, decoding successive top-level values until EOF.
func decodeResponses(t *testing.T, out []byte) []mcp.JSONRPCResponse {
	t.Helper()
	var resps []mcp.JSONRPCResponse
	dec := json.NewDecoder(bytes.NewReader(out))
	for {
		var r mcp.JSONRPCResponse
		err := dec.Decode(&r)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("decode response: %v", err)
		}
		resps = append(resps, r)
	}
	return resps
}

func TestHeroRequestsUseMCP20260728Metadata(t *testing.T) {
	raw, err := os.ReadFile("../hero-requests.jsonl")
	if err != nil {
		t.Fatalf("read hero request fixture: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	if len(lines) != 3 {
		t.Fatalf("hero request count = %d, want 3", len(lines))
	}

	for i, line := range lines {
		var req struct {
			Method string `json:"method"`
			Params struct {
				Meta map[string]json.RawMessage `json:"_meta"`
			} `json:"params"`
		}
		if err := json.Unmarshal([]byte(line), &req); err != nil {
			t.Fatalf("request %d is not valid JSON: %v", i+1, err)
		}
		if req.Method == "initialize" {
			t.Fatalf("request %d uses the removed initialize handshake", i+1)
		}

		var protocolVersion string
		if err := json.Unmarshal(req.Params.Meta["io.modelcontextprotocol/protocolVersion"], &protocolVersion); err != nil {
			t.Fatalf("request %d has invalid protocolVersion metadata: %v", i+1, err)
		}
		if protocolVersion != "2026-07-28" {
			t.Errorf("request %d protocolVersion = %q, want 2026-07-28", i+1, protocolVersion)
		}

		var capabilities map[string]json.RawMessage
		if err := json.Unmarshal(req.Params.Meta["io.modelcontextprotocol/clientCapabilities"], &capabilities); err != nil {
			t.Fatalf("request %d has invalid clientCapabilities metadata: %v", i+1, err)
		}
		if capabilities == nil {
			t.Errorf("request %d clientCapabilities must be a JSON object", i+1)
		}
	}
}

func TestServeAnswersRequestsAndSkipsNotifications(t *testing.T) {
	in := strings.Join([]string{
		`{"jsonrpc":"2.0","method":"notifications/progress"}`, // notification: no reply
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"filesystem.read","arguments":{"path":"notes.txt"},"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{},"io.modelcontextprotocol/clientInfo":{"name":"stub-test","version":"1"}}}}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"filesystem.write","arguments":{"path":"out.txt","content":"hi"},"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{},"io.modelcontextprotocol/clientInfo":{"name":"stub-test","version":"1"}}}}`,
		`{"jsonrpc":"2.0","id":3,"method":"demo/received-tools","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{},"io.modelcontextprotocol/clientInfo":{"name":"stub-test","version":"1"}}}}`,
	}, "\n") + "\n"

	var out bytes.Buffer
	if err := serve(strings.NewReader(in), &out); err != nil {
		t.Fatalf("serve: %v", err)
	}

	resps := decodeResponses(t, out.Bytes())
	// Three requests carry ids; the notification must not be answered.
	if len(resps) != 3 {
		t.Fatalf("expected 3 responses (notification skipped), got %d: %q", len(resps), out.String())
	}
	for i, resp := range resps {
		if !strings.Contains(string(resp.Result), `"resultType":"complete"`) {
			t.Errorf("response %d missing current MCP resultType: %s", i+1, resp.Result)
		}
	}

	// filesystem.read must echo the injected marker so the taint scenario works.
	readText := mcp.ResultText(resps[0].Result)
	if !strings.Contains(readText, injectedMarker) {
		t.Errorf("filesystem.read result missing marker %q; got %q", injectedMarker, readText)
	}
	// filesystem.write returns a benign confirmation, not an error.
	if resps[1].Error != nil {
		t.Errorf("filesystem.write: unexpected error %v", resps[1].Error)
	}
	if got := mcp.ResultText(resps[1].Result); got == "" {
		t.Errorf("filesystem.write: expected non-empty result text")
	}

	// The diagnostic method must report only tools/call requests, in order. It
	// is how the flagship demo proves a blocked write never reached upstream.
	var received struct {
		ReceivedTools []string `json:"receivedTools"`
	}
	if err := json.Unmarshal(resps[2].Result, &received); err != nil {
		t.Fatalf("decode received-tools result: %v", err)
	}
	want := []string{"filesystem.read", "filesystem.write"}
	if len(received.ReceivedTools) != len(want) {
		t.Fatalf("received tools = %v, want %v", received.ReceivedTools, want)
	}
	for i := range want {
		if received.ReceivedTools[i] != want[i] {
			t.Errorf("received tools = %v, want %v", received.ReceivedTools, want)
		}
	}
}

func TestServeSupportsLegacyInitialize(t *testing.T) {
	in := `{"jsonrpc":"2.0","id":7,"method":"initialize","params":{}}` + "\n"

	var out bytes.Buffer
	if err := serve(strings.NewReader(in), &out); err != nil {
		t.Fatalf("serve: %v", err)
	}

	resps := decodeResponses(t, out.Bytes())
	if len(resps) != 1 {
		t.Fatalf("expected 1 response, got %d", len(resps))
	}
	if string(resps[0].ID) != "7" || resps[0].Error != nil {
		t.Errorf("initialize: got id=%s err=%v", resps[0].ID, resps[0].Error)
	}
}

func TestServeToolsCallMissingNameIsInvalidParams(t *testing.T) {
	in := `{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"arguments":{}}}` + "\n"

	var out bytes.Buffer
	if err := serve(strings.NewReader(in), &out); err != nil {
		t.Fatalf("serve: %v", err)
	}

	resps := decodeResponses(t, out.Bytes())
	if len(resps) != 1 {
		t.Fatalf("expected 1 response, got %d", len(resps))
	}
	if resps[0].Error == nil {
		t.Fatalf("expected an error response for missing tool name")
	}
	if resps[0].Error.Code != mcp.ErrorCodeInvalidParams {
		t.Errorf("expected InvalidParams (%d), got %d", mcp.ErrorCodeInvalidParams, resps[0].Error.Code)
	}
}
