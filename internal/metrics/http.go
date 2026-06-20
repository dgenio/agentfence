package metrics

import (
	"net/http"
)

// Handler returns an http.Handler that serves c's current Snapshot in the
// Prometheus text-exposition format. It is the opt-in /metrics endpoint for the
// proxies: an operator points a scraper at it and nothing is sent anywhere the
// operator did not choose, consistent with AgentFence's no-telemetry posture.
//
// The handler responds to GET (and HEAD) only; other methods get 405.
func Handler(c *Counters) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		if r.Method == http.MethodHead {
			return
		}
		// A scrape that fails mid-write is the scraper's problem to retry; the
		// snapshot is already consistent, so there is nothing to roll back.
		_ = c.Snapshot().WritePrometheus(w)
	})
}

// Serve runs an HTTP server that exposes c's metrics on listenAddr at /metrics
// until ctx is cancelled, then shuts it down. It is started by the proxies when
// --metrics-listen is set. A root path returns a one-line pointer to /metrics.
func ServeMux(c *Counters) *http.ServeMux {
	mux := http.NewServeMux()
	mux.Handle("/metrics", Handler(c))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte("agentfence metrics: see /metrics\n"))
	})
	return mux
}
