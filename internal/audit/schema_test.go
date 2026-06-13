package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// schemaPath points at the canonical audit-event schema relative to this
// package directory (tests run with their package as the working directory).
const schemaPath = "../../schema/agentfence-audit-event.schema.json"

// jsonSchema is the minimal shape of the schema we need to assert drift.
type jsonSchema struct {
	Properties map[string]json.RawMessage `json:"properties"`
	Defs       map[string]struct {
		Properties map[string]json.RawMessage `json:"properties"`
	} `json:"$defs"`
}

func loadSchema(t *testing.T) jsonSchema {
	t.Helper()
	b, err := os.ReadFile(filepath.Clean(schemaPath))
	if err != nil {
		t.Fatalf("read schema: %v", err)
	}
	var s jsonSchema
	if err := json.Unmarshal(b, &s); err != nil {
		t.Fatalf("parse schema: %v", err)
	}
	return s
}

// jsonTagNames returns the set of JSON field names for a struct type, stripping
// ",omitempty" and ignoring "-".
func jsonTagNames(t reflect.Type) map[string]bool {
	names := map[string]bool{}
	for i := 0; i < t.NumField(); i++ {
		tag := t.Field(i).Tag.Get("json")
		if tag == "" || tag == "-" {
			continue
		}
		name := strings.Split(tag, ",")[0]
		if name != "" {
			names[name] = true
		}
	}
	return names
}

// TestSchemaMatchesEventStruct fails if the audit-event JSON Schema and the Go
// Event struct drift apart, so neither can be changed without the other.
func TestSchemaMatchesEventStruct(t *testing.T) {
	s := loadSchema(t)
	got := jsonTagNames(reflect.TypeOf(Event{}))

	assertSameKeys(t, "Event", got, s.Properties)
}

// TestSchemaMatchesMemoryWriteStruct guards the nested memory_write summary.
func TestSchemaMatchesMemoryWriteStruct(t *testing.T) {
	s := loadSchema(t)
	def, ok := s.Defs["memoryWriteSummary"]
	if !ok {
		t.Fatal("schema is missing $defs.memoryWriteSummary")
	}
	got := jsonTagNames(reflect.TypeOf(MemoryWriteSummary{}))
	assertSameKeys(t, "MemoryWriteSummary", got, def.Properties)
}

func assertSameKeys(t *testing.T, what string, structFields map[string]bool, schemaProps map[string]json.RawMessage) {
	t.Helper()
	for name := range structFields {
		if _, ok := schemaProps[name]; !ok {
			t.Errorf("%s field %q is missing from the JSON Schema", what, name)
		}
	}
	for name := range schemaProps {
		if !structFields[name] {
			t.Errorf("JSON Schema property %q has no matching %s struct field", name, what)
		}
	}
}

// TestCurrentSchemaVersionDocumented ensures the schema advertises the version
// the writer actually emits, so a version bump cannot silently skip the schema.
func TestCurrentSchemaVersionDocumented(t *testing.T) {
	b, err := os.ReadFile(filepath.Clean(schemaPath))
	if err != nil {
		t.Fatalf("read schema: %v", err)
	}
	if !strings.Contains(string(b), `"`+CurrentSchemaVersion+`"`) {
		t.Errorf("schema does not mention CurrentSchemaVersion %q; update the examples in %s", CurrentSchemaVersion, schemaPath)
	}
}
