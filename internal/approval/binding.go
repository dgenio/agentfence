package approval

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"sync/atomic"
	"time"

	"github.com/dgenio/agentfence/internal/exactjson"
	"github.com/dgenio/agentfence/internal/policy"
)

// BindingDigestAlgorithm identifies the v1 approval-binding projection. It is
// deliberately brand-neutral so a product rename cannot invalidate durable
// approval evidence.
const BindingDigestAlgorithm = "approval-binding-json-v1"

// Binding identifies the exact action + effective policy an approval applies
// to. Server/tool identity evidence joins this contract in the later #221
// integration slice; changing the v1 projection after release requires a new
// algorithm identifier.
type Binding struct {
	ActionDigest string `json:"action_digest"`
	PolicyDigest string `json:"policy_digest"`
}

// NewBinding validates the exact action and resolved-policy identities that an
// approval is about.
func NewBinding(actionDigest, policyDigest string) (Binding, error) {
	if err := validateDigest(actionDigest, policy.ToolActionDigestAlgorithm); err != nil {
		return Binding{}, fmt.Errorf("approval binding: action digest: %w", err)
	}
	if err := validateDigest(policyDigest, policy.ResolvedPolicyDigestAlgorithm); err != nil {
		return Binding{}, fmt.Errorf("approval binding: policy digest: %w", err)
	}
	return Binding{ActionDigest: actionDigest, PolicyDigest: policyDigest}, nil
}

// Digest returns the deterministic identity of this exact action/policy pair.
func (b Binding) Digest() (string, error) {
	if _, err := NewBinding(b.ActionDigest, b.PolicyDigest); err != nil {
		return "", err
	}
	raw, err := json.Marshal(b)
	if err != nil {
		return "", fmt.Errorf("approval binding: marshal: %w", err)
	}
	canonical, err := exactjson.Canonicalize(raw)
	if err != nil {
		return "", fmt.Errorf("approval binding: canonicalize: %w", err)
	}
	sum := sha256.Sum256(canonical)
	return BindingDigestAlgorithm + ":sha256:" + hex.EncodeToString(sum[:]), nil
}

type permitState struct {
	consumed atomic.Bool
}

// OneShotPermit is an in-process, single-use authorization to execute one
// exact Binding before expiry. It is intentionally not a reusable token or
// identity credential; it exists so the synchronous approval path can enforce
// replay/substitution/expiry invariants explicitly.
//
// Its security-relevant fields are private and copies share the same state, so
// copying a permit value cannot reset consumption or rewrite its binding.
type OneShotPermit struct {
	bindingDigest string
	issuedAt      time.Time
	expiresAt     time.Time
	state         *permitState
}

// NewOneShotPermit creates a permit for binding with an explicit finite
// validity interval. Zero timestamps or a non-positive interval are rejected.
func NewOneShotPermit(binding Binding, issuedAt, expiresAt time.Time) (*OneShotPermit, error) {
	digest, err := binding.Digest()
	if err != nil {
		return nil, err
	}
	if issuedAt.IsZero() {
		return nil, fmt.Errorf("approval permit: issued_at is required")
	}
	if expiresAt.IsZero() {
		return nil, fmt.Errorf("approval permit: expires_at is required")
	}
	if !expiresAt.After(issuedAt) {
		return nil, fmt.Errorf("approval permit: expires_at must be after issued_at")
	}
	return &OneShotPermit{
		bindingDigest: digest,
		issuedAt:      issuedAt,
		expiresAt:     expiresAt,
		state:         &permitState{},
	}, nil
}

// BindingDigest returns the immutable approval-binding identity this permit was
// issued for.
func (p *OneShotPermit) BindingDigest() string {
	if p == nil {
		return ""
	}
	return p.bindingDigest
}

// IssuedAt returns the permit's issuance time.
func (p *OneShotPermit) IssuedAt() time.Time {
	if p == nil {
		return time.Time{}
	}
	return p.issuedAt
}

// ExpiresAt returns the permit's exclusive expiry boundary.
func (p *OneShotPermit) ExpiresAt() time.Time {
	if p == nil {
		return time.Time{}
	}
	return p.expiresAt
}

// Consume authorizes exactly one execution of binding before the permit
// expires. Mismatch, expiry, and replay all fail closed. Concurrent consumers
// and copied permit values cannot both succeed.
func (p *OneShotPermit) Consume(binding Binding, now time.Time) error {
	if p == nil || p.state == nil {
		return fmt.Errorf("approval permit: invalid permit")
	}
	digest, err := binding.Digest()
	if err != nil {
		return err
	}
	if digest != p.bindingDigest {
		return fmt.Errorf("approval permit: binding mismatch")
	}
	if now.IsZero() {
		return fmt.Errorf("approval permit: current time is required")
	}
	if now.Before(p.issuedAt) {
		return fmt.Errorf("approval permit: current time precedes issuance")
	}
	if !now.Before(p.expiresAt) {
		return fmt.Errorf("approval permit: expired")
	}
	if !p.state.consumed.CompareAndSwap(false, true) {
		return fmt.Errorf("approval permit: already consumed")
	}
	return nil
}

// Consumed reports whether this permit has already authorized an execution.
func (p *OneShotPermit) Consumed() bool {
	return p != nil && p.state != nil && p.state.consumed.Load()
}

func validateDigest(value, algorithm string) error {
	prefix := algorithm + ":sha256:"
	if !strings.HasPrefix(value, prefix) {
		return fmt.Errorf("must use %s:sha256:<64 lowercase hex>", algorithm)
	}
	hexPart := strings.TrimPrefix(value, prefix)
	if len(hexPart) != sha256.Size*2 {
		return fmt.Errorf("must contain a 64-character SHA-256 digest")
	}
	decoded, err := hex.DecodeString(hexPart)
	if err != nil || hex.EncodeToString(decoded) != hexPart {
		return fmt.Errorf("digest must be lowercase hexadecimal")
	}
	return nil
}
