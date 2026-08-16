package mcp

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestParseToolCallParamsEmptyInputKeepsHistoricalError(t *testing.T) {
	for _, input := range []string{"", "   \n\t"} {
		_, err := ParseToolCallParams(json.RawMessage(input))
		if err == nil {
			t.Fatalf("ParseToolCallParams(%q) unexpectedly succeeded", input)
		}
		if !strings.Contains(err.Error(), "unexpected end of JSON input") {
			t.Fatalf("ParseToolCallParams(%q) error = %q, want historical empty-input error", input, err)
		}
	}
}
