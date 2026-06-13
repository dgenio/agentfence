package audit

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dgenio/agentfence/internal/policy"
)

func newTestSigner(t *testing.T) *Signer {
	t.Helper()
	_, priv, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	s, err := NewSigner(priv)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	return s
}

func TestWriterSignsEvents(t *testing.T) {
	signer := newTestSigner(t)
	buf := &bytes.Buffer{}
	w := NewWriterOptions(buf, Options{Signer: signer})
	if err := w.Write(Event{CallID: "c1", Tool: "fs.read", Decision: policy.DecisionAllow}); err != nil {
		t.Fatalf("Write: %v", err)
	}

	verified, unsigned, err := VerifySignatures(bytes.NewReader(buf.Bytes()), signer.Public())
	if err != nil {
		t.Fatalf("VerifySignatures: %v", err)
	}
	if verified != 1 || unsigned != 0 {
		t.Fatalf("verified=%d unsigned=%d, want 1/0", verified, unsigned)
	}
}

func TestSigningAndChainingCompose(t *testing.T) {
	signer := newTestSigner(t)
	buf := &bytes.Buffer{}
	w := NewWriterOptions(buf, Options{TamperEvident: true, Signer: signer})
	for i := 0; i < 3; i++ {
		if err := w.Write(Event{CallID: "c", Tool: "t", Decision: policy.DecisionDeny}); err != nil {
			t.Fatalf("Write: %v", err)
		}
	}
	// Both the chain and the signatures must verify over the same bytes.
	if n, err := VerifyChain(bytes.NewReader(buf.Bytes())); err != nil || n != 3 {
		t.Fatalf("VerifyChain n=%d err=%v", n, err)
	}
	if v, _, err := VerifySignatures(bytes.NewReader(buf.Bytes()), signer.Public()); err != nil || v != 3 {
		t.Fatalf("VerifySignatures v=%d err=%v", v, err)
	}
}

func TestVerifySignatureDetectsTampering(t *testing.T) {
	signer := newTestSigner(t)
	buf := &bytes.Buffer{}
	w := NewWriterOptions(buf, Options{Signer: signer})
	if err := w.Write(Event{CallID: "c1", Tool: "fs.read", Decision: policy.DecisionDeny, Reason: "blocked"}); err != nil {
		t.Fatalf("Write: %v", err)
	}
	// Flip a deny to allow without re-signing: the signature must no longer match.
	tampered := bytes.Replace(buf.Bytes(), []byte(`"decision":"deny"`), []byte(`"decision":"allow"`), 1)
	_, _, err := VerifySignatures(bytes.NewReader(tampered), signer.Public())
	var ve *VerifyError
	if !errors.As(err, &ve) {
		t.Fatalf("expected *VerifyError, got %v", err)
	}
}

func TestVerifySignaturesUnsignedLog(t *testing.T) {
	buf := &bytes.Buffer{}
	w := NewWriter(buf)
	_ = w.Write(Event{CallID: "c1", Tool: "t", Decision: policy.DecisionAllow})
	_, priv, _ := GenerateKeyPair()
	s, _ := NewSigner(priv)
	verified, unsigned, err := VerifySignatures(bytes.NewReader(buf.Bytes()), s.Public())
	if err != nil {
		t.Fatalf("VerifySignatures: %v", err)
	}
	if verified != 0 || unsigned != 1 {
		t.Fatalf("verified=%d unsigned=%d, want 0/1", verified, unsigned)
	}
}

func TestKeyPairFileRoundTrip(t *testing.T) {
	dir := t.TempDir()
	priv := filepath.Join(dir, "audit.key")
	pub := filepath.Join(dir, "audit.pub")
	pk, sk, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	if err := WriteKeyPairFiles(priv, pub, pk, sk); err != nil {
		t.Fatalf("WriteKeyPairFiles: %v", err)
	}
	// Refuses to clobber an existing private key.
	if err := WriteKeyPairFiles(priv, pub, pk, sk); err == nil {
		t.Fatal("expected refusal to overwrite existing private key")
	}

	loadedPriv, err := LoadPrivateKey(priv)
	if err != nil {
		t.Fatalf("LoadPrivateKey: %v", err)
	}
	loadedPub, err := LoadPublicKey(pub)
	if err != nil {
		t.Fatalf("LoadPublicKey: %v", err)
	}

	// A signature from the loaded private key verifies with the loaded public key.
	signer, err := NewSigner(loadedPriv)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	e := Event{SchemaVersion: CurrentSchemaVersion, CallID: "c", Tool: "t", Decision: policy.DecisionAllow}
	sig, err := signer.signEvent(e)
	if err != nil {
		t.Fatalf("signEvent: %v", err)
	}
	e.Signature = sig
	if err := VerifySignature(e, loadedPub); err != nil {
		t.Fatalf("VerifySignature: %v", err)
	}
}

func TestLoadPrivateKeyRejectsNonPEM(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.key")
	if err := os.WriteFile(path, []byte("not a pem file"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPrivateKey(path); err == nil || !strings.Contains(err.Error(), "no PEM block") {
		t.Fatalf("expected no-PEM error, got %v", err)
	}
}
