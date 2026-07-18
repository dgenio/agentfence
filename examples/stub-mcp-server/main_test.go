package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
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

func TestServeAnswersRequestsAndSkipsNotifications(t *testing.T) {
	in := strings.Join([]string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`, // notification: no reply
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"filesystem.read","arguments":{"path":"notes.txt"}}}`,
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"filesystem.write","arguments":{"path":"out.txt","content":"hi"}}}`,
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

	// initialize
	if string(resps[0].ID) != "1" || resps[0].Error != nil {
		t.Errorf("initialize: got id=%s err=%v", resps[0].ID, resps[0].Error)
	}

	// filesystem.read must echo the injected marker so the taint scenario works.
	readText := mcp.ResultText(resps[1].Result)
	if !strings.Contains(readText, injectedMarker) {
		t.Errorf("filesystem.read result missing marker %q; got %q", injectedMarker, readText)
	}

	// filesystem.write returns a benign confirmation, not an error.
	if resps[2].Error != nil {
		t.Errorf("filesystem.write: unexpected error %v", resps[2].Error)
	}
	if got := mcp.ResultText(resps[2].Result); got == "" {
		t.Errorf("filesystem.write: expected non-empty result text")
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
