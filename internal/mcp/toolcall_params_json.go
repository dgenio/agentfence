package mcp

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"

	"github.com/dgenio/agentfence/internal/exactjson"
)

// UnmarshalJSON preserves JSON number tokens inside Arguments instead of
// converting them to float64. MCP tool arguments are authorization input; a
// large integer must not be rounded before AgentFence evaluates or records it.
//
// The exact-json preflight also rejects ambiguous duplicate keys and invalid
// raw UTF-8 before encoding/json can collapse or replace them. Authorization
// must operate on a request representation with one unambiguous meaning.
func (p *ToolCallParams) UnmarshalJSON(data []byte) error {
	if _, err := exactjson.Canonicalize(data); err != nil {
		return fmt.Errorf("tools/call params: ambiguous or invalid JSON: %w", err)
	}

	type wireToolCallParams struct {
		Name      string                 `json:"name"`
		Arguments map[string]interface{} `json:"arguments,omitempty"`
	}

	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()

	var wire wireToolCallParams
	if err := dec.Decode(&wire); err != nil {
		return fmt.Errorf("tools/call params: decode JSON: %w", err)
	}
	if err := requireToolCallParamsEOF(dec); err != nil {
		return fmt.Errorf("tools/call params: %w", err)
	}

	*p = ToolCallParams(wire)
	return nil
}

func requireToolCallParamsEOF(dec *json.Decoder) error {
	var extra interface{}
	if err := dec.Decode(&extra); err != nil {
		if err == io.EOF {
			return nil
		}
		return err
	}
	return fmt.Errorf("multiple JSON values are not allowed")
}
