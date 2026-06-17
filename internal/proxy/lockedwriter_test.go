package proxy

import (
	"bytes"
	"sync"
	"testing"
)

// TestLockedWriterKeepsFramesAtomic hammers a single lockedWriter from many
// goroutines and asserts that no frame is interleaved with another. The proxy
// relies on this to keep JSON-RPC frames intact on the agent's stdout when the
// two relay directions write concurrently. Run under `-race` (make ci / CI) to
// also catch data races on the underlying writer.
func TestLockedWriterKeepsFramesAtomic(t *testing.T) {
	const (
		goroutines    = 32
		writesEach    = 50
		frameBodyByte = 256
	)

	var buf bytes.Buffer
	lw := &lockedWriter{w: &buf}

	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		// Each goroutine owns one printable byte ('A'..) so a complete frame is
		// a run of a single distinct byte — interleaving would mix bytes within
		// a line and be detectable. The range stays clear of '\n'/'\r' so a
		// frame body never introduces a spurious line break.
		ch := byte('A' + g)
		go func() {
			defer wg.Done()
			frame := append(bytes.Repeat([]byte{ch}, frameBodyByte), '\n')
			for i := 0; i < writesEach; i++ {
				if _, err := lw.Write(frame); err != nil {
					t.Errorf("Write: %v", err)
					return
				}
			}
		}()
	}
	wg.Wait()

	frames := bytes.Split(bytes.TrimRight(buf.Bytes(), "\n"), []byte("\n"))
	if len(frames) != goroutines*writesEach {
		t.Fatalf("got %d frames, want %d", len(frames), goroutines*writesEach)
	}
	for _, frame := range frames {
		if len(frame) != frameBodyByte {
			t.Fatalf("frame length = %d, want %d (interleaved write?)", len(frame), frameBodyByte)
		}
		if n := bytes.Count(frame, []byte{frame[0]}); n != len(frame) {
			t.Fatalf("frame mixes bytes (interleaved write): %d of %d bytes match first", n, len(frame))
		}
	}
}
