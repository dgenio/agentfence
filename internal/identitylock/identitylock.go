// Package identitylock defines the operator-reviewed lock artifact used to bind
// policy grants to a specific configured upstream and MCP tool descriptor.
//
// This package is intentionally pure: it parses, validates, and fingerprints
// evidence but does not alter runtime policy decisions. Enforcement belongs to
// a later #221 slice after the lock contract has been reviewed and tested.
package identitylock

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"

	"github.com/dgenio/agentfence/internal/exactjson"
)

const (
	// SchemaVersion is the on-disk identity-lock schema version.
	SchemaVersion = "1"
	// Canonicalization names the exact JSON byte contract used for descriptor
	// fingerprints. It is deliberately brand-neutral.
	Canonicalization = exactjson.Algorithm
)

var sha256DigestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// Lock is an operator-reviewed collection of upstream and tool identities.
type Lock struct {
	SchemaVersion    string              `json:"schema_version"`
	Canonicalization string              `json:"canonicalization"`
	Upstreams        map[string]Upstream `json:"upstreams"`
}

// Upstream identifies one operator-configured mediation boundary.
type Upstream struct {
	Transport            string          `json:"transport"`
	UpstreamConfigSHA256 string          `json:"upstream_config_sha256"`
	Tools                map[string]Tool `json:"tools"`
}

// Tool pins the exact canonical descriptor the operator reviewed.
type Tool struct {
	DescriptorSHA256 string `json:"descriptor_sha256"`
}

// Parse parses exactly one strict JSON identity lock.
//
// Duplicate object keys are rejected by exactjson before decoding, and
// DisallowUnknownFields keeps typos from silently changing the security model.
func Parse(data []byte) (Lock, error) {
	canonical, err := exactjson.Canonicalize(data)
	if err != nil {
		return Lock{}, fmt.Errorf("identity lock: canonicalize: %w", err)
	}

	dec := json.NewDecoder(bytes.NewReader(canonical))
	dec.DisallowUnknownFields()
	dec.UseNumber()

	var lock Lock
	if err := dec.Decode(&lock); err != nil {
		return Lock{}, fmt.Errorf("identity lock: decode: %w", err)
	}
	if err := requireEOF(dec); err != nil {
		return Lock{}, fmt.Errorf("identity lock: %w", err)
	}
	if err := lock.Validate(); err != nil {
		return Lock{}, err
	}
	return lock, nil
}

// Validate checks the lock's versioned invariants.
func (l Lock) Validate() error {
	if l.SchemaVersion != SchemaVersion {
		return fmt.Errorf("identity lock: unsupported schema_version %q (want %q)", l.SchemaVersion, SchemaVersion)
	}
	if l.Canonicalization != Canonicalization {
		return fmt.Errorf("identity lock: unsupported canonicalization %q (want %q)", l.Canonicalization, Canonicalization)
	}
	if len(l.Upstreams) == 0 {
		return fmt.Errorf("identity lock: upstreams must not be empty")
	}

	for _, upstreamRef := range sortedKeys(l.Upstreams) {
		if strings.TrimSpace(upstreamRef) != upstreamRef {
			return fmt.Errorf("identity lock: upstream reference %q must not contain leading or trailing whitespace", upstreamRef)
		}
		upstream := l.Upstreams[upstreamRef]
		switch upstream.Transport {
		case "stdio", "http":
		default:
			return fmt.Errorf("identity lock: upstream %q: unsupported transport %q", upstreamRef, upstream.Transport)
		}
		if !sha256DigestPattern.MatchString(upstream.UpstreamConfigSHA256) {
			return fmt.Errorf("identity lock: upstream %q: upstream_config_sha256 must be sha256:<64 lowercase hex>", upstreamRef)
		}
		if len(upstream.Tools) == 0 {
			return fmt.Errorf("identity lock: upstream %q: tools must not be empty", upstreamRef)
		}
		for _, toolName := range sortedKeys(upstream.Tools) {
			if strings.TrimSpace(toolName) != toolName {
				return fmt.Errorf("identity lock: upstream %q: tool name %q must not contain leading or trailing whitespace", upstreamRef, toolName)
			}
			tool := upstream.Tools[toolName]
			if !sha256DigestPattern.MatchString(tool.DescriptorSHA256) {
				return fmt.Errorf("identity lock: upstream %q tool %q: descriptor_sha256 must be sha256:<64 lowercase hex>", upstreamRef, toolName)
			}
		}
	}
	return nil
}

// DescriptorDigest returns a deterministic SHA-256 fingerprint of the complete
// canonical JSON tool descriptor.
//
// The root must be an object. This function does not assert provenance or
// publisher identity; it only gives content identity to evidence the operator
// reviewed. Duplicate keys and invalid UTF-8 fail via exactjson.
func DescriptorDigest(descriptor []byte) (string, error) {
	canonical, err := exactjson.Canonicalize(descriptor)
	if err != nil {
		return "", fmt.Errorf("tool descriptor: canonicalize: %w", err)
	}
	if len(canonical) == 0 || canonical[0] != '{' {
		return "", fmt.Errorf("tool descriptor: root must be a JSON object")
	}
	sum := sha256.Sum256(canonical)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

// Tool returns a pinned tool from an upstream without conflating an absent
// upstream/tool with an all-zero Tool value.
func (l Lock) Tool(upstreamRef, toolName string) (Tool, bool) {
	upstream, ok := l.Upstreams[upstreamRef]
	if !ok {
		return Tool{}, false
	}
	tool, ok := upstream.Tools[toolName]
	return tool, ok
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

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
