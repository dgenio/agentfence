package mcp

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
)

// UnmarshalJSON preserves JSON numeric values in MCP tool-call arguments as
// json.Number instead of converting them to float64. Authorization evidence
// must not collapse distinct on-wire numeric arguments before evaluation.
func (p *ToolCallParams) UnmarshalJSON(data []byte) error {
	// Preserve json.Unmarshal's historical empty/whitespace-only parse error.
	// json.Decoder.Decode would otherwise return the less actionable io.EOF.
	if len(bytes.TrimSpace(data)) == 0 {
		return fmt.Errorf("unexpected end of JSON input")
	}

	type wireToolCallParams struct {
		Name      string                 `json:"name"`
		Arguments map[string]interface{} `json:"arguments,omitempty"`
	}

	var wire wireToolCallParams
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if err := dec.Decode(&wire); err != nil {
		return err
	}

	var extra interface{}
	if err := dec.Decode(&extra); err != io.EOF {
		if err == nil {
			return fmt.Errorf("mcp: tools/call params must contain a single JSON value")
		}
		return err
	}

	p.Name = wire.Name
	p.Arguments = wire.Arguments
	return nil
}
