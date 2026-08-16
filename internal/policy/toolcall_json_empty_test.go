package policy

import (
	"strings"
	"testing"
)

func TestParseToolCallEmptyInputKeepsHistoricalError(t *testing.T) {
	for _, input := range []string{"", "   \n\t"} {
		_, err := ParseToolCall([]byte(input))
		if err == nil {
			t.Fatalf("ParseToolCall(%q) unexpectedly succeeded", input)
		}
		if !strings.Contains(err.Error(), "unexpected end of JSON input") {
			t.Fatalf("ParseToolCall(%q) error = %q, want historical empty-input error", input, err)
		}
	}
}
