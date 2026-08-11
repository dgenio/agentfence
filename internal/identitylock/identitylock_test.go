package identitylock

import (
	"strings"
	"testing"
)

const digestA = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
const digestB = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

func TestDescriptorDigestIgnoresObjectOrderAndWhitespace(t *testing.T) {
	left, err := DescriptorDigest([]byte(` {"name":"filesystem.write","inputSchema":{"type":"object","properties":{"b":{"type":"number"},"a":{"type":"integer"}}},"description":"write"} `))
	if err != nil {
		t.Fatalf("DescriptorDigest(left) error = %v", err)
	}
	right, err := DescriptorDigest([]byte(`{"description":"write","inputSchema":{"properties":{"a":{"type":"integer"},"b":{"type":"number"}},"type":"object"},"name":"filesystem.write"}`))
	if err != nil {
		t.Fatalf("DescriptorDigest(right) error = %v", err)
	}
	if left != right {
		t.Fatalf("equivalent descriptor digests differ:\n%s\n%s", left, right)
	}
}

func TestDescriptorDigestChangesForRetainedDescriptorFields(t *testing.T) {
	base, err := DescriptorDigest([]byte(`{"name":"demo","description":"read data","inputSchema":{"type":"object"}}`))
	if err != nil {
		t.Fatal(err)
	}
	changed, err := DescriptorDigest([]byte(`{"name":"demo","description":"write data","inputSchema":{"type":"object"}}`))
	if err != nil {
		t.Fatal(err)
	}
	if base == changed {
		t.Fatal("descriptor change must change digest")
	}
}

func TestDescriptorDigestPreservesExactNumbers(t *testing.T) {
	first, err := DescriptorDigest([]byte(`{"name":"demo","_meta":{"limit":9007199254740992}}`))
	if err != nil {
		t.Fatal(err)
	}
	second, err := DescriptorDigest([]byte(`{"name":"demo","_meta":{"limit":9007199254740993}}`))
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("distinct >2^53 descriptor numbers must not collapse")
	}
}

func TestDescriptorDigestRejectsAmbiguousOrNonObjectInput(t *testing.T) {
	cases := []string{
		`{"name":"demo","name":"other"}`,
		`["demo"]`,
		`"demo"`,
	}
	for _, input := range cases {
		t.Run(input, func(t *testing.T) {
			if _, err := DescriptorDigest([]byte(input)); err == nil {
				t.Fatalf("DescriptorDigest(%s) unexpectedly succeeded", input)
			}
		})
	}
}

func TestParseValidLock(t *testing.T) {
	data := `{
	  "canonicalization": "exact-json-v1",
	  "schema_version": "1",
	  "upstreams": {
	    "workspace-files": {
	      "tools": {
	        "filesystem.write": {"descriptor_sha256": "` + digestB + `"},
	        "filesystem.read": {"descriptor_sha256": "` + digestA + `"}
	      },
	      "upstream_config_sha256": "` + digestA + `",
	      "transport": "stdio"
	    }
	  }
	}`

	lock, err := Parse([]byte(data))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if lock.SchemaVersion != SchemaVersion || lock.Canonicalization != Canonicalization {
		t.Fatalf("unexpected lock header: %#v", lock)
	}
	tool, ok := lock.Tool("workspace-files", "filesystem.write")
	if !ok || tool.DescriptorSHA256 != digestB {
		t.Fatalf("Tool() = %#v, %v; want %s", tool, ok, digestB)
	}
	if _, ok := lock.Tool("workspace-files", "missing"); ok {
		t.Fatal("missing tool unexpectedly found")
	}
	if _, ok := lock.Tool("missing", "filesystem.write"); ok {
		t.Fatal("missing upstream unexpectedly found")
	}
}

func TestParseRejectsUnknownFieldsAndDuplicateKeys(t *testing.T) {
	base := `{"schema_version":"1","canonicalization":"exact-json-v1","upstreams":{"u":{"transport":"stdio","upstream_config_sha256":"` + digestA + `","tools":{"demo":{"descriptor_sha256":"` + digestB + `"}}}}}`

	unknown := strings.Replace(base, `"transport":"stdio"`, `"transport":"stdio","credential":"secret"`, 1)
	if _, err := Parse([]byte(unknown)); err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("unknown-field Parse() error = %v, want strict rejection", err)
	}

	duplicate := strings.Replace(base, `"transport":"stdio"`, `"transport":"stdio","transport":"http"`, 1)
	if _, err := Parse([]byte(duplicate)); err == nil || !strings.Contains(err.Error(), "duplicate object key") {
		t.Fatalf("duplicate-key Parse() error = %v, want duplicate rejection", err)
	}
}

func TestParseRejectsUnsupportedVersionCanonicalizationAndTransport(t *testing.T) {
	valid := `{"schema_version":"1","canonicalization":"exact-json-v1","upstreams":{"u":{"transport":"stdio","upstream_config_sha256":"` + digestA + `","tools":{"demo":{"descriptor_sha256":"` + digestB + `"}}}}}`

	cases := []struct {
		name string
		data string
		want string
	}{
		{"schema", strings.Replace(valid, `"schema_version":"1"`, `"schema_version":"2"`, 1), "unsupported schema_version"},
		{"canonicalization", strings.Replace(valid, `"canonicalization":"exact-json-v1"`, `"canonicalization":"other"`, 1), "unsupported canonicalization"},
		{"transport", strings.Replace(valid, `"transport":"stdio"`, `"transport":"grpc"`, 1), "unsupported transport"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse([]byte(tc.data))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Parse() error = %v, want containing %q", err, tc.want)
			}
		})
	}
}

func TestValidateRejectsMissingOrMalformedEvidence(t *testing.T) {
	cases := []struct {
		name string
		lock Lock
		want string
	}{
		{
			name: "no upstreams",
			lock: Lock{SchemaVersion: SchemaVersion, Canonicalization: Canonicalization},
			want: "upstreams must not be empty",
		},
		{
			name: "bad config digest",
			lock: Lock{SchemaVersion: SchemaVersion, Canonicalization: Canonicalization, Upstreams: map[string]Upstream{"u": {Transport: "http", UpstreamConfigSHA256: "sha256:ABC", Tools: map[string]Tool{"demo": {DescriptorSHA256: digestA}}}}},
			want: "upstream_config_sha256",
		},
		{
			name: "no tools",
			lock: Lock{SchemaVersion: SchemaVersion, Canonicalization: Canonicalization, Upstreams: map[string]Upstream{"u": {Transport: "stdio", UpstreamConfigSHA256: digestA}}},
			want: "tools must not be empty",
		},
		{
			name: "bad descriptor digest",
			lock: Lock{SchemaVersion: SchemaVersion, Canonicalization: Canonicalization, Upstreams: map[string]Upstream{"u": {Transport: "stdio", UpstreamConfigSHA256: digestA, Tools: map[string]Tool{"demo": {DescriptorSHA256: "sha256:1234"}}}}},
			want: "descriptor_sha256",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.lock.Validate(); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Validate() error = %v, want containing %q", err, tc.want)
			}
		})
	}
}
