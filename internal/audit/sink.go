package audit

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Sink receives a copy of every successfully written audit event for delivery
// to an external, operator-controlled destination. Implementations MUST be
// non-blocking in Emit: a slow or unreachable destination must never stall
// policy enforcement. Events that cannot be buffered are dropped and counted.
type Sink interface {
	// Emit hands a single serialized event line (JSON, no trailing newline) to
	// the sink. It returns immediately.
	Emit(event []byte)
	// Close flushes buffered events (best-effort, bounded) and releases
	// resources. It reports the number of dropped events via the configured
	// logger.
	Close() error
}

const (
	// sinkBufferSize bounds in-flight events per sink. Past this the sink drops
	// events rather than blocking the Write path.
	sinkBufferSize = 1024
	// sinkBatchSize and sinkFlushInterval control how eagerly a sink delivers.
	sinkBatchSize     = 64
	sinkFlushInterval = time.Second
	sinkDialTimeout   = 5 * time.Second
)

// asyncSink is the shared machinery for buffered, batched, non-blocking
// delivery. Concrete sinks supply deliver and closeFn.
type asyncSink struct {
	name    string
	ch      chan []byte
	wg      sync.WaitGroup
	dropped int64
	logger  io.Writer
	deliver func(batch [][]byte) error
	closeFn func() error
}

func newAsyncSink(name string, logger io.Writer, deliver func([][]byte) error, closeFn func() error) *asyncSink {
	a := &asyncSink{
		name:    name,
		ch:      make(chan []byte, sinkBufferSize),
		logger:  logger,
		deliver: deliver,
		closeFn: closeFn,
	}
	a.wg.Add(1)
	go a.run()
	return a
}

func (a *asyncSink) run() {
	defer a.wg.Done()
	ticker := time.NewTicker(sinkFlushInterval)
	defer ticker.Stop()
	batch := make([][]byte, 0, sinkBatchSize)
	flush := func() {
		if len(batch) == 0 {
			return
		}
		if err := a.deliver(batch); err != nil && a.logger != nil {
			fmt.Fprintf(a.logger, "AgentFence: warning: audit sink %s delivery failed: %v\n", a.name, err)
		}
		batch = batch[:0]
	}
	for {
		select {
		case ev, ok := <-a.ch:
			if !ok {
				flush()
				return
			}
			batch = append(batch, ev)
			if len(batch) >= sinkBatchSize {
				flush()
			}
		case <-ticker.C:
			flush()
		}
	}
}

func (a *asyncSink) Emit(event []byte) {
	// Copy: the caller reuses its marshalling buffer after Emit returns.
	cp := make([]byte, len(event))
	copy(cp, event)
	select {
	case a.ch <- cp:
	default:
		atomic.AddInt64(&a.dropped, 1)
	}
}

func (a *asyncSink) Close() error {
	close(a.ch)
	a.wg.Wait()
	if d := atomic.LoadInt64(&a.dropped); d > 0 && a.logger != nil {
		fmt.Fprintf(a.logger, "AgentFence: warning: audit sink %s dropped %d event(s) due to a full buffer\n", a.name, d)
	}
	if a.closeFn != nil {
		return a.closeFn()
	}
	return nil
}

// fanoutSink delivers each event to every wrapped sink.
type fanoutSink struct {
	sinks []Sink
}

func (f *fanoutSink) Emit(event []byte) {
	for _, s := range f.sinks {
		s.Emit(event)
	}
}

func (f *fanoutSink) Close() error {
	var firstErr error
	for _, s := range f.sinks {
		if err := s.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// ParseSinks builds a single Sink (a fan-out when more than one spec is given)
// from sink specifications. Supported schemes:
//
//	http://…, https://…       — batched POST of newline-delimited JSON
//	syslog://host:port        — RFC 5424 messages over UDP (default)
//	syslog+tcp://host:port    — RFC 5424 messages over TCP
//
// It returns (nil, nil) when specs is empty. logger receives delivery and
// drop warnings (typically os.Stderr).
func ParseSinks(specs []string, logger io.Writer) (Sink, error) {
	var sinks []Sink
	for _, spec := range specs {
		spec = strings.TrimSpace(spec)
		if spec == "" {
			continue
		}
		s, err := parseSink(spec, logger)
		if err != nil {
			// Close any sinks already started before failing.
			for _, started := range sinks {
				_ = started.Close()
			}
			return nil, err
		}
		sinks = append(sinks, s)
	}
	switch len(sinks) {
	case 0:
		return nil, nil
	case 1:
		return sinks[0], nil
	default:
		return &fanoutSink{sinks: sinks}, nil
	}
}

func parseSink(spec string, logger io.Writer) (Sink, error) {
	u, err := url.Parse(spec)
	if err != nil {
		return nil, fmt.Errorf("audit: invalid --audit-sink %q: %w", spec, err)
	}
	switch u.Scheme {
	case "http", "https":
		return newHTTPSink(spec, logger), nil
	case "syslog":
		return newSyslogSink("udp", u.Host, logger)
	case "syslog+tcp":
		return newSyslogSink("tcp", u.Host, logger)
	default:
		return nil, fmt.Errorf("audit: unsupported --audit-sink scheme %q (use http, https, syslog, or syslog+tcp)", u.Scheme)
	}
}

// newHTTPSink posts batches of events to endpoint as newline-delimited JSON.
func newHTTPSink(endpoint string, logger io.Writer) Sink {
	client := &http.Client{Timeout: 10 * time.Second}
	deliver := func(batch [][]byte) error {
		body := bytes.Join(batch, []byte("\n"))
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/x-ndjson")
		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		_, _ = io.Copy(io.Discard, resp.Body)
		if resp.StatusCode >= 300 {
			return fmt.Errorf("unexpected status %s", resp.Status)
		}
		return nil
	}
	return newAsyncSink("http", logger, deliver, nil)
}

// newSyslogSink sends each event as an RFC 5424 message over network proto.
func newSyslogSink(proto, host string, logger io.Writer) (Sink, error) {
	if host == "" {
		return nil, fmt.Errorf("audit: syslog sink requires host:port")
	}
	conn, err := net.DialTimeout(proto, host, sinkDialTimeout)
	if err != nil {
		return nil, fmt.Errorf("audit: dial syslog %s://%s: %w", proto, host, err)
	}
	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "-"
	}
	pid := os.Getpid()
	// PRI 134 = facility local0 (16)*8 + severity informational (6).
	const pri = 134
	deliver := func(batch [][]byte) error {
		for _, ev := range batch {
			ts := time.Now().UTC().Format(time.RFC3339Nano)
			msg := fmt.Sprintf("<%d>1 %s %s agentfence %d - - %s\n", pri, ts, hostname, pid, ev)
			if _, err := conn.Write([]byte(msg)); err != nil {
				return err
			}
		}
		return nil
	}
	name := "syslog+" + proto
	return newAsyncSink(name, logger, deliver, conn.Close), nil
}
