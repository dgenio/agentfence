package policy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
)

// UnmarshalJSON preserves JSON numeric values in tool-call arguments as
// json.Number instead of converting them to float64. This is required before
// action fingerprinting can truthfully identify the exact semantic action:
// distinct integers above 2^53 must not collapse during parsing.
func (c *ToolCall) UnmarshalJSON(data []byte) error {
	// Preserve json.Unmarshal's historical empty/whitespace-only parse error.
	// json.Decoder.Decode would otherwise return the less actionable io.EOF.
	if len(bytes.TrimSpace(data)) == 0 {
		return fmt.Errorf("unexpected end of JSON input")
	}

	type wireToolCall struct {
		ID        string                 `json:"id"`
		Tool      string                 `json:"tool"`
		Arguments map[string]interface{} `json:"arguments"`
	}

	var wire wireToolCall
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if err := dec.Decode(&wire); err != nil {
		return err
	}

	// Keep json.Unmarshal's single-value behavior even though Decoder.Decode
	// itself would otherwise accept a second top-level JSON value.
	var extra interface{}
	if err := dec.Decode(&extra); err != io.EOF {
		if err == nil {
			return fmt.Errorf("tool call must contain a single JSON value")
		}
		return err
	}

	c.ID = wire.ID
	c.Tool = wire.Tool
	c.Arguments = wire.Arguments
	return nil
}
