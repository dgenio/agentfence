package policy

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestParseToolCallPreservesJSONNumberPrecision(t *testing.T) {
	call, err := ParseToolCall([]byte(`{"id":"c1","tool":"demo","arguments":{"low":9007199254740992,"high":9007199254740993,"decimal":0.1234567890123456789,"string":"1","nested":{"values":[9007199254740993,1.2300]}}}`))
	if err != nil {
		t.Fatalf("ParseToolCall() error = %v", err)
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

	wantNumber("low", call.Arguments["low"], "9007199254740992")
	wantNumber("high", call.Arguments["high"], "9007199254740993")
	wantNumber("decimal", call.Arguments["decimal"], "0.1234567890123456789")

	if got, ok := call.Arguments["string"].(string); !ok || got != "1" {
		t.Fatalf("string = %#v (%T), want string(\"1\")", call.Arguments["string"], call.Arguments["string"])
	}

	nested, ok := call.Arguments["nested"].(map[string]interface{})
	if !ok {
		t.Fatalf("nested type = %T, want map[string]interface{}", call.Arguments["nested"])
	}
	values, ok := nested["values"].([]interface{})
	if !ok || len(values) != 2 {
		t.Fatalf("nested.values = %#v (%T), want two-element []interface{}", nested["values"], nested["values"])
	}
	wantNumber("nested.values[0]", values[0], "9007199254740993")
	wantNumber("nested.values[1]", values[1], "1.2300")

	encoded, err := json.Marshal(call)
	if err != nil {
		t.Fatalf("json.Marshal(call) error = %v", err)
	}
	text := string(encoded)
	for _, token := range []string{
		`"low":9007199254740992`,
		`"high":9007199254740993`,
		`"decimal":0.1234567890123456789`,
		`"string":"1"`,
		`9007199254740993,1.2300`,
	} {
		if !strings.Contains(text, token) {
			t.Errorf("marshaled call %s does not contain %s", text, token)
		}
	}
}

func TestParseToolCallRejectsMultipleJSONValues(t *testing.T) {
	_, err := ParseToolCall([]byte(`{"id":"c1","tool":"demo"} {"id":"c2","tool":"demo"}`))
	if err == nil {
		t.Fatal("ParseToolCall() accepted multiple JSON values")
	}
}
