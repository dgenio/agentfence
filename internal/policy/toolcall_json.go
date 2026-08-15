package policy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"

	"github.com/dgenio/agentfence/internal/exactjson"
)

// UnmarshalJSON preserves the lexical value of JSON numbers inside Arguments.
//
// The default encoding/json behavior for interface{} decodes numbers as
// float64, which can silently round integers above 2^53. Tool-call arguments
// are part of AgentFence's authorization input, so distinct on-wire JSON
// values must stay distinct before policy evaluation, audit, and future action
// fingerprinting.
//
// The exact-json preflight also rejects ambiguous duplicate keys and invalid
// raw UTF-8 before encoding/json can collapse or replace them. Authorization
// must operate on a request representation with one unambiguous meaning.
func (c *ToolCall) UnmarshalJSON(data []byte) error {
	if _, err := exactjson.Canonicalize(data); err != nil {
		return fmt.Errorf("tool call: ambiguous or invalid JSON: %w", err)
	}

	type wireToolCall struct {
		ID        string                 `json:"id"`
		Tool      string                 `json:"tool"`
		Arguments map[string]interface{} `json:"arguments"`
	}

	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()

	var wire wireToolCall
	if err := dec.Decode(&wire); err != nil {
		return fmt.Errorf("tool call: decode JSON: %w", err)
	}
	if err := requireJSONEOF(dec); err != nil {
		return fmt.Errorf("tool call: %w", err)
	}

	*c = ToolCall(wire)
	return nil
}

func requireJSONEOF(dec *json.Decoder) error {
	var extra interface{}
	if err := dec.Decode(&extra); err != nil {
		if err == io.EOF {
			return nil
		}
		return err
	}
	return fmt.Errorf("multiple JSON values are not allowed")
}
