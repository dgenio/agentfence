package policy

import (
	"encoding/json"
	"testing"
)

func TestParseToolCallPreservesJSONNumbers(t *testing.T) {
	call, err := ParseToolCall([]byte(`{"id":"c1","tool":"example.run","arguments":{"a":9007199254740992,"b":9007199254740993,"decimal":1.2300,"string":"1","nested":{"n":9007199254740993},"array":[1,9007199254740993]}}`))
	if err != nil {
		t.Fatalf("ParseToolCall() error = %v", err)
	}

	assertJSONNumber(t, call.Arguments["a"], "9007199254740992")
	assertJSONNumber(t, call.Arguments["b"], "9007199254740993")
	assertJSONNumber(t, call.Arguments["decimal"], "1.2300")

	if got, ok := call.Arguments["string"].(string); !ok || got != "1" {
		t.Fatalf("string argument = %#v (%T), want string %q", call.Arguments["string"], call.Arguments["string"], "1")
	}

	nested, ok := call.Arguments["nested"].(map[string]interface{})
	if !ok {
		t.Fatalf("nested = %#v (%T), want map[string]interface{}", call.Arguments["nested"], call.Arguments["nested"])
	}
	assertJSONNumber(t, nested["n"], "9007199254740993")

	array, ok := call.Arguments["array"].([]interface{})
	if !ok || len(array) != 2 {
		t.Fatalf("array = %#v (%T), want two-element []interface{}", call.Arguments["array"], call.Arguments["array"])
	}
	assertJSONNumber(t, array[0], "1")
	assertJSONNumber(t, array[1], "9007199254740993")

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

func assertJSONNumber(t *testing.T, got interface{}, want string) {
	t.Helper()
	n, ok := got.(json.Number)
	if !ok {
		t.Fatalf("value = %#v (%T), want json.Number(%q)", got, got, want)
	}
	if n.String() != want {
		t.Fatalf("json.Number = %q, want %q", n.String(), want)
	}
}
