package exactjson

import (
	"strings"
	"testing"
)

func TestCanonicalizeIgnoresObjectOrderAndWhitespace(t *testing.T) {
	left, err := Canonicalize([]byte(` { "b" : 2 , "a" : { "y": true, "x": null } } `))
	if err != nil {
		t.Fatalf("Canonicalize(left) error = %v", err)
	}
	right, err := Canonicalize([]byte(`{"a":{"x":null,"y":true},"b":2}`))
	if err != nil {
		t.Fatalf("Canonicalize(right) error = %v", err)
	}
	if string(left) != string(right) {
		t.Fatalf("canonical bytes differ:\nleft  %s\nright %s", left, right)
	}
	if got, want := string(left), `{"a":{"x":null,"y":true},"b":2}`; got != want {
		t.Fatalf("Canonicalize() = %s, want %s", got, want)
	}
}

func TestCanonicalizePreservesExactNumberTokens(t *testing.T) {
	cases := []struct {
		input string
		want  string
	}{
		{`9007199254740992`, `9007199254740992`},
		{`9007199254740993`, `9007199254740993`},
		{`0.1234567890123456789`, `0.1234567890123456789`},
		{`1`, `1`},
		{`1.0`, `1.0`},
		{`1.00`, `1.00`},
		{`1e3`, `1e3`},
		{`1E+3`, `1E+3`},
		{`-0`, `-0`},
	}
	for _, tc := range cases {
		t.Run(tc.input, func(t *testing.T) {
			got, err := Canonicalize([]byte(tc.input))
			if err != nil {
				t.Fatalf("Canonicalize(%s) error = %v", tc.input, err)
			}
			if string(got) != tc.want {
				t.Fatalf("Canonicalize(%s) = %s, want %s", tc.input, got, tc.want)
			}
		})
	}

	one, _ := Canonicalize([]byte(`1`))
	onePointZero, _ := Canonicalize([]byte(`1.0`))
	if string(one) == string(onePointZero) {
		t.Fatal("1 and 1.0 must remain distinct exact representations")
	}
}

func TestCanonicalizePreservesTypesAndArrayOrder(t *testing.T) {
	number, err := Canonicalize([]byte(`{"value":1,"items":[1,"1",true,null]}`))
	if err != nil {
		t.Fatal(err)
	}
	stringValue, err := Canonicalize([]byte(`{"value":"1","items":[1,"1",true,null]}`))
	if err != nil {
		t.Fatal(err)
	}
	if string(number) == string(stringValue) {
		t.Fatal("JSON number and JSON string must remain distinct")
	}
	if got, want := string(number), `{"items":[1,"1",true,null],"value":1}`; got != want {
		t.Fatalf("canonical value = %s, want %s", got, want)
	}

	ordered, _ := Canonicalize([]byte(`[1,2,3]`))
	reversed, _ := Canonicalize([]byte(`[3,2,1]`))
	if string(ordered) == string(reversed) {
		t.Fatal("array order must remain significant")
	}
}

func TestCanonicalizeNormalizesStringEscapesWithoutHTMLEscaping(t *testing.T) {
	escaped, err := Canonicalize([]byte(`{"x":"\u0061<&>"}`))
	if err != nil {
		t.Fatal(err)
	}
	plain, err := Canonicalize([]byte(`{"x":"a<&>"}`))
	if err != nil {
		t.Fatal(err)
	}
	if string(escaped) != string(plain) {
		t.Fatalf("equivalent string values differ: %s vs %s", escaped, plain)
	}
	if got, want := string(escaped), `{"x":"a<&>"}`; got != want {
		t.Fatalf("canonical string = %s, want %s", got, want)
	}
}

func TestCanonicalizeRejectsDuplicateObjectKeys(t *testing.T) {
	for _, input := range []string{
		`{"a":1,"a":2}`,
		`{"outer":{"a":1,"a":2}}`,
		`[{"a":1,"a":2}]`,
	} {
		t.Run(input, func(t *testing.T) {
			_, err := Canonicalize([]byte(input))
			if err == nil {
				t.Fatal("expected duplicate-key rejection")
			}
			if !strings.Contains(err.Error(), "duplicate object key") {
				t.Fatalf("error = %v, want duplicate-object-key diagnostic", err)
			}
		})
	}
}

func TestCanonicalizeRejectsInvalidUTF8(t *testing.T) {
	input := []byte{'{', '"', 'x', '"', ':', '"', 0xff, '"', '}'}
	_, err := Canonicalize(input)
	if err == nil {
		t.Fatal("expected invalid UTF-8 rejection")
	}
	if !strings.Contains(err.Error(), "not valid UTF-8") {
		t.Fatalf("error = %v, want UTF-8 diagnostic", err)
	}
}

func TestCanonicalizeRejectsInvalidOrMultipleJSON(t *testing.T) {
	for _, input := range []string{
		``,
		`{"a":1} {"b":2}`,
		`{"a":`,
		`[1,]`,
	} {
		t.Run(input, func(t *testing.T) {
			if _, err := Canonicalize([]byte(input)); err == nil {
				t.Fatalf("Canonicalize(%q) unexpectedly succeeded", input)
			}
		})
	}
}

func TestAlgorithmIsBrandNeutralAndVersioned(t *testing.T) {
	if Algorithm != "exact-json-v1" {
		t.Fatalf("Algorithm = %q, want exact-json-v1", Algorithm)
	}
	for _, brand := range []string{"agentfence", "vericordon"} {
		if strings.Contains(strings.ToLower(Algorithm), brand) {
			t.Fatalf("Algorithm %q must not contain product brand %q", Algorithm, brand)
		}
	}
}
