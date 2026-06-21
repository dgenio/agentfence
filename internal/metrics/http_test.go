package metrics

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/dgenio/agentfence/internal/policy"
)

func TestHandlerServesPrometheus(t *testing.T) {
	c := New()
	c.Record(policy.DecisionDeny, "github.delete_repo", policy.ReasonCodePathDenied)

	srv := httptest.NewServer(Handler(c))
	defer srv.Close()

	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Errorf("Content-Type = %q, want text/plain prefix", ct)
	}
	buf := make([]byte, 4096)
	n, _ := resp.Body.Read(buf)
	if !strings.Contains(string(buf[:n]), "agentfence_decisions_total") {
		t.Errorf("metrics body missing decisions series:\n%s", buf[:n])
	}
}

func TestHandlerRejectsNonGet(t *testing.T) {
	srv := httptest.NewServer(Handler(New()))
	defer srv.Close()

	req, _ := http.NewRequest(http.MethodPost, srv.URL, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", resp.StatusCode)
	}
}

func TestServeMuxRoutesMetrics(t *testing.T) {
	srv := httptest.NewServer(ServeMux(New()))
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/metrics")
	if err != nil {
		t.Fatalf("GET /metrics: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("/metrics status = %d, want 200", resp.StatusCode)
	}

	root, err := http.Get(srv.URL + "/")
	if err != nil {
		t.Fatalf("GET /: %v", err)
	}
	root.Body.Close()
	if root.StatusCode != http.StatusOK {
		t.Errorf("/ status = %d, want 200", root.StatusCode)
	}
}
