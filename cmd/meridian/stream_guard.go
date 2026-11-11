package main

import (
	"bufio"
	"context"
	"errors"
	"net"
	"net/http"
	"time"
)

// streamStallTimeout bounds how long a streaming response may keep an upstream
// body open without the downstream consuming bytes. Go's ReverseProxy cancels
// the origin request when the client context ends, so an explicit abort on
// disconnect is already handled; the gap this closes is a client that stays
// connected but stops reading (paused player, dead Wi-Fi, half-open TCP). In
// that state a Write blocks forever, the origin keeps delivering the file, and
// the VPS pays for bytes nobody is watching — the traffic black hole that hurts
// small instances most.
const streamStallTimeout = 5 * time.Minute

// streamStallCheckInterval is how often progress is inspected. A stall is acted
// on only after streamStallTimeout has fully elapsed.
const streamStallCheckInterval = 30 * time.Second

var errStreamDownstreamStalled = errors.New("下游长时间无写入进展")

// streamGuard tracks write progress for one response and forces the connection
// closed once the downstream has been idle for streamStallTimeout.
type streamGuard struct {
	w         http.ResponseWriter
	lastWrite time.Time
	written   int64
	streaming bool
}

func newStreamGuard(w http.ResponseWriter) *streamGuard {
	return &streamGuard{w: w, lastWrite: time.Now()}
}

// wrap returns a ResponseWriter that records progress. Streaming responses are
// detected lazily: the first write after the response started counts.
func (g *streamGuard) wrap() http.ResponseWriter {
	return &streamGuardWriter{guard: g, ResponseWriter: g.w}
}

type streamGuardWriter struct {
	guard *streamGuard
	http.ResponseWriter
}

func (s *streamGuardWriter) Write(b []byte) (int, error) {
	n, err := s.ResponseWriter.Write(b)
	if n > 0 {
		s.guard.streaming = true
		s.guard.written += int64(n)
		s.guard.lastWrite = time.Now()
	}
	return n, err
}

func (s *streamGuardWriter) Flush() {
	if f, ok := s.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (s *streamGuardWriter) Unwrap() http.ResponseWriter { return s.ResponseWriter }

func (s *streamGuardWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if h, ok := s.ResponseWriter.(http.Hijacker); ok {
		return h.Hijack()
	}
	return nil, nil, errors.New("hijack not supported")
}

// watch aborts the response once writes stop making progress. It returns a stop
// function so the goroutine never outlives the request.
func (g *streamGuard) watch(ctx context.Context) func() {
	done := make(chan struct{})
	go func() {
		ticker := time.NewTicker(streamStallCheckInterval)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ctx.Done():
				return
			case <-ticker.C:
				if !g.streaming || time.Since(g.lastWrite) < streamStallTimeout {
					continue
				}
				// A past write deadline unblocks any in-flight Write immediately,
				// which unwinds ReverseProxy's copy loop and closes the upstream
				// body instead of letting it drain the whole file.
				controller := http.NewResponseController(g.w)
				_ = controller.SetWriteDeadline(time.Now())
				return
			}
		}
	}()
	return func() { close(done) }
}

// isUpstreamCancellation reports whether an error came from the origin read
// being aborted, which happens after a stall or client disconnect and must not
// be logged as an upstream failure.
func isUpstreamCancellation(err error) bool {
	if err == nil {
		return false
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}
	return errors.Is(err, context.Canceled) || errors.Is(err, errStreamDownstreamStalled)
}
