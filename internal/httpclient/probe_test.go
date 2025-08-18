package httpclient

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestProbeReadsBodyAndHeaders(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "AmazonS3")
		w.Header().Set("X-Amz-Request-Id", "ABC123")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("<Error><Code>NoSuchBucket</Code></Error>"))
	}))
	defer srv.Close()

	c := New(5*time.Second, 0, "")
	res := c.Probe(context.Background(), strings.TrimPrefix(srv.URL, "http://"))

	if res.Err != "" {
		t.Fatalf("unexpected error: %s", res.Err)
	}
	if res.StatusCode != http.StatusNotFound {
		t.Fatalf("status: %d", res.StatusCode)
	}
	if !strings.Contains(res.Body, "NoSuchBucket") {
		t.Fatalf("body: %q", res.Body)
	}
	if res.Headers["X-Amz-Request-Id"] != "ABC123" {
		t.Fatalf("headers: %v", res.Headers)
	}
}

func TestProbeDoesNotFollowRedirects(t *testing.T) {
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			hits++
			http.Redirect(w, r, "/moved", http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := New(5*time.Second, 0, "")
	res := c.Probe(context.Background(), strings.TrimPrefix(srv.URL, "http://"))

	if res.StatusCode != http.StatusFound {
		t.Fatalf("redirect must be surfaced, not followed: got %d", res.StatusCode)
	}
	if hits != 1 {
		t.Fatalf("redirect target must not be fetched, hits=%d", hits)
	}
}

func TestProbeTruncatesHugeBodies(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat("A", 4*maxBody)))
	}))
	defer srv.Close()

	c := New(10*time.Second, 0, "")
	res := c.Probe(context.Background(), strings.TrimPrefix(srv.URL, "http://"))

	if len(res.Body) > maxBody {
		t.Fatalf("body not bounded: %d bytes", len(res.Body))
	}
}

func TestProbeEmptyHost(t *testing.T) {
	c := New(time.Second, 0, "")
	if res := c.Probe(context.Background(), "  "); res.Err == "" {
		t.Fatal("empty host must be reported as an error, not panic")
	}
}

func TestProbeUnreachableIsErrorNotPanic(t *testing.T) {
	c := New(500*time.Millisecond, 0, "")
	res := c.Probe(context.Background(), "this-host-does-not-exist.invalid")
	if res.Err == "" {
		t.Fatal("expected a probe error for an unresolvable host")
	}
	if len(res.Err) > 200 {
		t.Fatalf("error text not trimmed: %d chars", len(res.Err))
	}
}

func TestProbeRespectsContextCancellation(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(2 * time.Second)
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	c := New(5*time.Second, 0, "")
	start := time.Now()
	res := c.Probe(ctx, strings.TrimPrefix(srv.URL, "http://"))

	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("cancellation ignored: took %s", elapsed)
	}
	if res.Err == "" {
		t.Fatal("expected cancellation to surface as an error")
	}
}

func TestRateLimiterDisabledPassesThrough(t *testing.T) {
	l := newRateLimiter(0)
	start := time.Now()
	for i := 0; i < 100; i++ {
		if err := l.Wait(context.Background()); err != nil {
			t.Fatalf("unexpected error: %s", err)
		}
	}
	if elapsed := time.Since(start); elapsed > 200*time.Millisecond {
		t.Fatalf("disabled limiter must not throttle: %s", elapsed)
	}
}

func TestRateLimiterEnforcesRate(t *testing.T) {
	l := newRateLimiter(10)
	start := time.Now()
	for i := 0; i < 20; i++ {
		if err := l.Wait(context.Background()); err != nil {
			t.Fatalf("unexpected error: %s", err)
		}
	}
	elapsed := time.Since(start)
	// 20 requests at 10/s with a burst of 10 must take at least ~0.9s.
	if elapsed < 800*time.Millisecond {
		t.Fatalf("limiter let %d requests through in %s at 10 rps", 20, elapsed)
	}
}

func TestRateLimiterResettable(t *testing.T) {
	l := newRateLimiter(1)
	start := time.Now()
	if err := l.Wait(context.Background()); err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	if err := l.Wait(context.Background()); err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	if elapsed := time.Since(start); elapsed < 500*time.Millisecond {
		t.Fatalf("1 rps must pace requests, took %s", elapsed)
	}

	// The old implementation ignored this; the new one must apply it.
	l.SetRate(0)
	start = time.Now()
	for i := 0; i < 50; i++ {
		if err := l.Wait(context.Background()); err != nil {
			t.Fatalf("unexpected error: %s", err)
		}
	}
	if elapsed := time.Since(start); elapsed > 200*time.Millisecond {
		t.Fatalf("SetRate(0) must disable limiting, took %s", elapsed)
	}
}

func TestRateLimiterHonoursContext(t *testing.T) {
	l := newRateLimiter(1) // burst of 1, so the second call must block
	if err := l.Wait(context.Background()); err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := l.Wait(ctx); err == nil {
		t.Fatal("expected context deadline error while blocked")
	}
}

func TestSetProxyValidates(t *testing.T) {
	c := New(time.Second, 0, "")
	if err := c.SetProxy("not a url"); err == nil {
		t.Fatal("invalid proxy must be rejected")
	}
	if err := c.SetProxy("http://127.0.0.1:8080"); err != nil {
		t.Fatalf("valid proxy rejected: %s", err)
	}
	if err := c.SetProxy(""); err != nil {
		t.Fatalf("clearing proxy failed: %s", err)
	}
	if c.transport.Proxy != nil {
		t.Fatal("proxy not cleared")
	}
}

func TestClientConcurrentProbeSafety(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	host := strings.TrimPrefix(srv.URL, "http://")
	c := New(5*time.Second, 0, "")
	c.SetRate(0)

	done := make(chan error, 16)
	for i := 0; i < 16; i++ {
		go func() {
			res := c.Probe(context.Background(), host)
			if res.Err != "" {
				done <- errorString(res.Err)
			}
			done <- nil
		}()
	}
	for i := 0; i < 16; i++ {
		if err := <-done; err != nil {
			t.Fatalf("concurrent probe failed: %s", err)
		}
	}
}

type errorString string

func (e errorString) Error() string { return string(e) }
