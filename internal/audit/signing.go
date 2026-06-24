package audit

import (
	"bufio"
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
)

// PEM block types for the on-disk key files. PKCS#8 / PKIX are the standard,
// stdlib-supported encodings for Ed25519 keys, so the files interoperate with
// openssl and other tooling without a third-party dependency.
const (
	privateKeyPEMType = "PRIVATE KEY"
	publicKeyPEMType  = "PUBLIC KEY"
)

// Signer signs audit events with an Ed25519 private key. It is safe for
// concurrent use: ed25519.Sign is stateless and the key is read-only.
type Signer struct {
	priv ed25519.PrivateKey
}

// NewSigner returns a Signer backed by priv. It returns an error if priv is
// not a valid Ed25519 private key.
func NewSigner(priv ed25519.PrivateKey) (*Signer, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("audit: invalid Ed25519 private key size %d (want %d)", len(priv), ed25519.PrivateKeySize)
	}
	return &Signer{priv: priv}, nil
}

// Public returns the verifying key corresponding to the signer.
func (s *Signer) Public() ed25519.PublicKey {
	return s.priv.Public().(ed25519.PublicKey)
}

// signEvent returns the base64-encoded Ed25519 signature over e's canonical
// digest. The caller stores the result in e.Signature.
func (s *Signer) signEvent(e Event) (string, error) {
	digest, err := signingDigest(e)
	if err != nil {
		return "", err
	}
	sig := ed25519.Sign(s.priv, digest[:])
	return base64.StdEncoding.EncodeToString(sig), nil
}

// VerifySignature checks the base64 Ed25519 signature stored in e.Signature
// against pub. It returns nil if the signature is valid, ErrNoSignature if the
// event carries no signature, or a descriptive error otherwise.
func VerifySignature(e Event, pub ed25519.PublicKey) error {
	if e.Signature == "" {
		return ErrNoSignature
	}
	if len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("audit: invalid Ed25519 public key size %d (want %d)", len(pub), ed25519.PublicKeySize)
	}
	sig, err := base64.StdEncoding.DecodeString(e.Signature)
	if err != nil {
		return fmt.Errorf("audit: decode signature: %w", err)
	}
	digest, err := signingDigest(e)
	if err != nil {
		return err
	}
	if !ed25519.Verify(pub, digest[:], sig) {
		return errors.New("audit: signature does not match event")
	}
	return nil
}

// ErrNoSignature reports that an event has no signature to verify. Callers that
// require every event to be signed treat this as a failure; callers verifying a
// possibly-unsigned log treat it as "skip".
var ErrNoSignature = errors.New("audit: event is not signed")

// VerifySignatures walks the JSONL audit log in r and verifies every event's
// Ed25519 signature against pub. It returns the number of signed events that
// verified and the number of unsigned events skipped. The first invalid
// signature aborts with a *VerifyError pinpointing the event.
//
// An entirely unsigned log returns (0, n, nil): there is nothing to attest, but
// nothing is wrong either. Callers that require signatures should treat a zero
// verified count on a non-empty log as a failure.
func VerifySignatures(r io.Reader, pub ed25519.PublicKey) (verified int, unsigned int, err error) {
	if len(pub) != ed25519.PublicKeySize {
		return 0, 0, fmt.Errorf("audit: invalid Ed25519 public key size %d (want %d)", len(pub), ed25519.PublicKeySize)
	}
	br := bufio.NewReader(r)
	eventNumber := 0
	for {
		line, readErr := br.ReadBytes('\n')
		line = bytes.TrimRight(line, "\r\n")
		if len(bytes.TrimSpace(line)) == 0 {
			if readErr != nil {
				if errors.Is(readErr, io.EOF) {
					break
				}
				return verified, unsigned, fmt.Errorf("audit: read input: %w", readErr)
			}
			continue
		}
		eventNumber++

		var e Event
		if uerr := json.Unmarshal(line, &e); uerr != nil {
			return verified, unsigned, &VerifyError{EventNumber: eventNumber, Reason: fmt.Sprintf("invalid JSON: %s", uerr)}
		}
		switch err := VerifySignature(e, pub); {
		case err == nil:
			verified++
		case errors.Is(err, ErrNoSignature):
			unsigned++
		default:
			return verified, unsigned, &VerifyError{EventNumber: eventNumber, Reason: err.Error()}
		}

		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				break
			}
			return verified, unsigned, fmt.Errorf("audit: read input: %w", readErr)
		}
	}
	return verified, unsigned, nil
}

// GenerateKeyPair returns a fresh Ed25519 key pair using crypto/rand.
func GenerateKeyPair() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return ed25519.GenerateKey(rand.Reader)
}

// MarshalPrivateKeyPEM encodes priv as a PKCS#8 PEM block.
func MarshalPrivateKeyPEM(priv ed25519.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("audit: marshal private key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: privateKeyPEMType, Bytes: der}), nil
}

// MarshalPublicKeyPEM encodes pub as a PKIX PEM block.
func MarshalPublicKeyPEM(pub ed25519.PublicKey) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("audit: marshal public key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: publicKeyPEMType, Bytes: der}), nil
}

// LoadPrivateKey reads and parses a PKCS#8 PEM Ed25519 private key from path.
func LoadPrivateKey(path string) (ed25519.PrivateKey, error) {
	b, err := os.ReadFile(path) // #nosec G304 -- key path is supplied by the operator running this local tool
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, fmt.Errorf("audit: %s: no PEM block found", path)
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("audit: parse private key %s: %w", path, err)
	}
	priv, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("audit: %s: not an Ed25519 private key (%T)", path, key)
	}
	return priv, nil
}

// LoadPublicKey reads and parses a PKIX PEM Ed25519 public key from path.
func LoadPublicKey(path string) (ed25519.PublicKey, error) {
	b, err := os.ReadFile(path) // #nosec G304 -- key path is supplied by the operator running this local tool
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, fmt.Errorf("audit: %s: no PEM block found", path)
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("audit: parse public key %s: %w", path, err)
	}
	pub, ok := key.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("audit: %s: not an Ed25519 public key (%T)", path, key)
	}
	return pub, nil
}

// WriteKeyPairFiles writes priv to privPath (0o600) and pub to pubPath (0o644).
// It refuses to overwrite an existing private key so a stray re-run cannot
// silently destroy signing material.
func WriteKeyPairFiles(privPath, pubPath string, pub ed25519.PublicKey, priv ed25519.PrivateKey) error {
	if _, err := os.Stat(privPath); err == nil {
		return fmt.Errorf("audit: refusing to overwrite existing private key %q", privPath)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	privPEM, err := MarshalPrivateKeyPEM(priv)
	if err != nil {
		return err
	}
	pubPEM, err := MarshalPublicKeyPEM(pub)
	if err != nil {
		return err
	}
	if err := os.WriteFile(privPath, privPEM, 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(pubPath, pubPEM, 0o644); err != nil { // #nosec G306 -- an Ed25519 *public* key is non-secret and intentionally world-readable (0o644)
		return err
	}
	return nil
}

// ensure ed25519.PrivateKey satisfies crypto.Signer at compile time; the audit
// package only needs the typed key, but this guards against an accidental
// import-path swap that would silently change the key type.
var _ crypto.Signer = ed25519.PrivateKey(nil)
