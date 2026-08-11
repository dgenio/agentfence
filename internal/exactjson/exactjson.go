// Package exactjson canonicalizes JSON while preserving the exact lexical
// representation of JSON numbers.
//
// This is intentionally not RFC 8785 / JCS. AgentFence needs to distinguish
// authorization inputs such as 9007199254740992 and 9007199254740993 without
// forcing them through IEEE-754, and it also deliberately treats 1, 1.0, and
// 1.00 as distinct exact request representations.
package exactjson

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"sort"
)

// Algorithm identifies the current canonical byte contract. It is deliberately
// brand-neutral so product naming changes do not invalidate future content
// identities built on these bytes.
const Algorithm = "exact-json-v1"

// Canonicalize parses exactly one JSON value and emits deterministic bytes.
//
// Properties:
//   - object keys are sorted lexicographically;
//   - array order is preserved;
//   - insignificant whitespace is removed;
//   - strings are emitted as JSON with HTML escaping disabled;
//   - booleans and null use their JSON literals;
//   - json.Number token text is preserved exactly.
//
// Consequently, semantically different JSON types remain different and
// lexically different numeric tokens such as 1 and 1.0 remain different.
func Canonicalize(data []byte) ([]byte, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()

	var value interface{}
	if err := dec.Decode(&value); err != nil {
		return nil, fmt.Errorf("exactjson: decode: %w", err)
	}
	if err := requireEOF(dec); err != nil {
		return nil, fmt.Errorf("exactjson: %w", err)
	}

	var out bytes.Buffer
	if err := writeValue(&out, value); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

func requireEOF(dec *json.Decoder) error {
	var extra interface{}
	if err := dec.Decode(&extra); err != nil {
		if err == io.EOF {
			return nil
		}
		return err
	}
	return fmt.Errorf("multiple JSON values are not allowed")
}

func writeValue(out *bytes.Buffer, value interface{}) error {
	switch v := value.(type) {
	case nil:
		out.WriteString("null")
		return nil
	case bool:
		if v {
			out.WriteString("true")
		} else {
			out.WriteString("false")
		}
		return nil
	case string:
		return writeString(out, v)
	case json.Number:
		encoded, err := json.Marshal(v)
		if err != nil {
			return fmt.Errorf("exactjson: invalid number %q: %w", v.String(), err)
		}
		out.Write(encoded)
		return nil
	case []interface{}:
		out.WriteByte('[')
		for i, item := range v {
			if i > 0 {
				out.WriteByte(',')
			}
			if err := writeValue(out, item); err != nil {
				return err
			}
		}
		out.WriteByte(']')
		return nil
	case map[string]interface{}:
		keys := make([]string, 0, len(v))
		for key := range v {
			keys = append(keys, key)
		}
		sort.Strings(keys)

		out.WriteByte('{')
		for i, key := range keys {
			if i > 0 {
				out.WriteByte(',')
			}
			if err := writeString(out, key); err != nil {
				return err
			}
			out.WriteByte(':')
			if err := writeValue(out, v[key]); err != nil {
				return err
			}
		}
		out.WriteByte('}')
		return nil
	default:
		return fmt.Errorf("exactjson: unsupported decoded type %T", value)
	}
}

func writeString(out *bytes.Buffer, value string) error {
	var encoded bytes.Buffer
	enc := json.NewEncoder(&encoded)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(value); err != nil {
		return fmt.Errorf("exactjson: encode string: %w", err)
	}
	b := encoded.Bytes()
	if len(b) == 0 || b[len(b)-1] != '\n' {
		return fmt.Errorf("exactjson: string encoder produced unexpected output")
	}
	out.Write(b[:len(b)-1])
	return nil
}
