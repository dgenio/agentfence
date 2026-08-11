package mcp

import (
	"encoding/json"
	"testing"
)

func TestParseToolCallParamsPreservesJSONNumbers(t *testing.T) {
	params, err := ParseToolCallParams(json.RawMessage(`{"name":"example.run","arguments":{"a":9007199254740992,"b":9007199254740993,"number":1,"string":"1","nested":{"n":9007199254740993},"array":[1,9007199254740993]}}`))
	if err != nil {
		t.Fatalf("ParseToolCallParams() error = %v", err)
	}

	assertMCPJSONNumber(t, params.Arguments["a"], "9007199254740992")
	assertMCPJSONNumber(t, params.Arguments["b"], "9007199254740993")
	assertMCPJSONNumber(t, params.Arguments["number"], "1")

	if got, ok := params.Arguments["string"].(string); !ok || got != "1" {
		t.Fatalf("string argument = %#v (%T), want string %q", params.Arguments["string"], params.Arguments["string"], "1")
	}

	nested, ok := params.Arguments["nested"].(map[string]interface{})
	if !ok {
		t.Fatalf("nested = %#v (%T), want map[string]interface{}", params.Arguments["nested"], params.Arguments["nested"])
	}
	assertMCPJSONNumber(t, nested["n"], "9007199254740993")

	array, ok := params.Arguments["array"].([]interface{})
	if !ok || len(array) != 2 {
		t.Fatalf("array = %#v (%T), want two-element []interface{}", params.Arguments["array"], params.Arguments["array"])
	}
	assertMCPJSONNumber(t, array[0], "1")
	assertMCPJSONNumber(t, array[1], "9007199254740993")

	call := params.ToToolCall("c1")
	roundTrip, err := json.Marshal(call.Arguments)
	if err != nil {
		t.Fatalf("json.Marshal(arguments) error = %v", err)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(roundTrip, &raw); err != nil {
		t.Fatalf("round-trip JSON invalid: %v", err)
	}
	if got := string(raw["b"]); got != "9007199254740993" {
		t.Fatalf("round-trip b = %s, want 9007199254740993", got)
	}
	if got := string(raw["string"]); got != `"1"` {
		t.Fatalf("round-trip string = %s, want quoted JSON string", got)
	}
}

func assertMCPJSONNumber(t *testing.T, got interface{}, want string) {
	t.Helper()
	n, ok := got.(json.Number)
	if !ok {
		t.Fatalf("value = %#v (%T), want json.Number(%q)", got, got, want)
	}
	if n.String() != want {
		t.Fatalf("json.Number = %q, want %q", n.String(), want)
	}
}
