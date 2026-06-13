package audit

import (
	"bytes"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/dgenio/agentfence/internal/policy"
)

func TestHTTPSinkDeliversEvents(t *testing.T) {
	var (
		mu       sync.Mutex
		received []byte
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if ct := r.Header.Get("Content-Type"); ct != "application/x-ndjson" {
			t.Errorf("Content-Type = %q, want application/x-ndjson", ct)
		}
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		received = append(received, b...)
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	sink, err := ParseSinks([]string{srv.URL}, io.Discard)
	if err != nil {
		t.Fatalf("ParseSinks: %v", err)
	}

	buf := &bytes.Buffer{}
	w := NewWriterOptions(buf, Options{Sink: sink})
	if err := w.Write(Event{CallID: "c1", Tool: "fs.read", Decision: policy.DecisionDeny, Reason: "blocked"}); err != nil {
		t.Fatalf("Write: %v", err)
	}
	// Close flushes synchronously.
	if err := sink.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	mu.Lock()
	got := string(received)
	mu.Unlock()
	if !bytes.Contains([]byte(got), []byte(`"call_id":"c1"`)) {
		t.Fatalf("delivered body missing event: %q", got)
	}
}

func TestSyslogSinkDeliversEvents(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}
	defer pc.Close()

	got := make(chan string, 1)
	go func() {
		b := make([]byte, 4096)
		n, _, err := pc.ReadFrom(b)
		if err != nil {
			return
		}
		got <- string(b[:n])
	}()

	sink, err := ParseSinks([]string{"syslog://" + pc.LocalAddr().String()}, io.Discard)
	if err != nil {
		t.Fatalf("ParseSinks: %v", err)
	}
	buf := &bytes.Buffer{}
	w := NewWriterOptions(buf, Options{Sink: sink})
	if err := w.Write(Event{CallID: "sysc1", Tool: "t", Decision: policy.DecisionAllow}); err != nil {
		t.Fatalf("Write: %v", err)
	}

	select {
	case msg := <-got:
		if !bytes.Contains([]byte(msg), []byte("agentfence")) || !bytes.Contains([]byte(msg), []byte(`"call_id":"sysc1"`)) {
			t.Fatalf("unexpected syslog message: %q", msg)
		}
		if msg[0] != '<' {
			t.Fatalf("syslog message missing RFC 5424 priority prefix: %q", msg)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for syslog datagram")
	}
	_ = sink.Close()
}

func TestParseSinksRejectsUnknownScheme(t *testing.T) {
	if _, err := ParseSinks([]string{"ftp://example.com"}, io.Discard); err == nil {
		t.Fatal("expected error for unsupported scheme")
	}
}

func TestParseSinksEmpty(t *testing.T) {
	sink, err := ParseSinks(nil, io.Discard)
	if err != nil {
		t.Fatalf("ParseSinks: %v", err)
	}
	if sink != nil {
		t.Fatal("expected nil sink for empty specs")
	}
}

func TestParseSinksFanout(t *testing.T) {
	var hits int
	var mu sync.Mutex
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		mu.Lock()
		hits++
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	})
	s1 := httptest.NewServer(handler)
	defer s1.Close()
	s2 := httptest.NewServer(handler)
	defer s2.Close()

	sink, err := ParseSinks([]string{s1.URL, s2.URL}, io.Discard)
	if err != nil {
		t.Fatalf("ParseSinks: %v", err)
	}
	buf := &bytes.Buffer{}
	w := NewWriterOptions(buf, Options{Sink: sink})
	_ = w.Write(Event{CallID: "c", Tool: "t", Decision: policy.DecisionAllow})
	_ = sink.Close()

	mu.Lock()
	defer mu.Unlock()
	if hits != 2 {
		t.Fatalf("expected both sinks to receive the event, got %d deliveries", hits)
	}
}
