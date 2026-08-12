package mcp

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestParseToolCallParamsPreservesJSONNumberPrecision(t *testing.T) {
	params, err := ParseToolCallParams(json.RawMessage(`{"name":"demo","arguments":{"low":9007199254740992,"high":9007199254740993,"decimal":1234567890.123456789,"string":"1","nested":[{"n":9007199254740993}]}}`))
	if err != nil {
		t.Fatalf("ParseToolCallParams() error = %v", err)
	}

	wantNumber := func(path string, got interface{}, want string) {
		t.Helper()
		n, ok := got.(json.Number)
		if !ok {
			t.Fatalf("%s type = %T, want json.Number", path, got)
		}
		if n.String() != want {
			t.Fatalf("%s = %q, want %q", path, n.String(), want)
		}
	}

	wantNumber("low", params.Arguments["low"], "9007199254740992")
	wantNumber("high", params.Arguments["high"], "9007199254740993")
	wantNumber("decimal", params.Arguments["decimal"], "1234567890.123456789")

	if got, ok := params.Arguments["string"].(string); !ok || got != "1" {
		t.Fatalf("string = %#v (%T), want string(\"1\")", params.Arguments["string"], params.Arguments["string"])
	}

	nested, ok := params.Arguments["nested"].([]interface{})
	if !ok || len(nested) != 1 {
		t.Fatalf("nested = %#v (%T), want one-element []interface{}", params.Arguments["nested"], params.Arguments["nested"])
	}
	obj, ok := nested[0].(map[string]interface{})
	if !ok {
		t.Fatalf("nested[0] type = %T, want map[string]interface{}", nested[0])
	}
	wantNumber("nested[0].n", obj["n"], "9007199254740993")

	call := params.ToToolCall("c1")
	encoded, err := json.Marshal(call.Arguments)
	if err != nil {
		t.Fatalf("json.Marshal(arguments) error = %v", err)
	}
	text := string(encoded)
	for _, token := range []string{
		`"low":9007199254740992`,
		`"high":9007199254740993`,
		`"decimal":1234567890.123456789`,
		`"string":"1"`,
	} {
		if !strings.Contains(text, token) {
			t.Errorf("marshaled arguments %s do not contain %s", text, token)
		}
	}
}

func TestParseToolCallParamsRejectsMultipleJSONValues(t *testing.T) {
	_, err := ParseToolCallParams(json.RawMessage(`{"name":"first"} {"name":"second"}`))
	if err == nil {
		t.Fatal("ParseToolCallParams() accepted multiple JSON values")
	}
}
