package audit

import (
	"bufio"
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestHistoricalAgentFenceV4EvidenceRemainsVerifiable(t *testing.T) {
	logPath := filepath.Join("testdata", "agentfence-v4-signed-chain.jsonl")
	raw, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read historical log: %v", err)
	}

	if n, err := VerifyChain(bytes.NewReader(raw)); err != nil || n != 2 {
		t.Fatalf("VerifyChain() n=%d err=%v, want 2 valid historical events", n, err)
	}

	pub, err := LoadPublicKey(filepath.Join("testdata", "agentfence-v4-signing.pub.pem"))
	if err != nil {
		t.Fatalf("LoadPublicKey: %v", err)
	}
	verified, unsigned, err := VerifySignatures(bytes.NewReader(raw), pub)
	if err != nil || verified != 2 || unsigned != 0 {
		t.Fatalf("VerifySignatures() verified=%d unsigned=%d err=%v, want 2/0/nil", verified, unsigned, err)
	}

	anchorRaw, err := os.ReadFile(filepath.Join("testdata", "agentfence-v4-anchor.json"))
	if err != nil {
		t.Fatalf("read historical anchor: %v", err)
	}
	var anchor Anchor
	if err := json.Unmarshal(anchorRaw, &anchor); err != nil {
		t.Fatalf("decode historical anchor: %v", err)
	}
	if err := VerifyAgainstAnchor(bytes.NewReader(raw), anchor); err != nil {
		t.Fatalf("VerifyAgainstAnchor: %v", err)
	}

	scanner := bufio.NewScanner(bytes.NewReader(raw))
	count := 0
	for scanner.Scan() {
		count++
		var event Event
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			t.Fatalf("decode event %d: %v", count, err)
		}
		if event.SchemaVersion != "4" {
			t.Fatalf("event %d schema_version=%q, want historical v4", count, event.SchemaVersion)
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("scan historical log: %v", err)
	}
	if count != 2 {
		t.Fatalf("historical event count=%d, want 2", count)
	}
}
