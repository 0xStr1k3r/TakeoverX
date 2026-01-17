package discovery

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestMain shortens the retry backoff so the retry and fallback tests finish
// quickly without weakening what they assert.
func TestMain(m *testing.M) {
	ctRetryBaseBackoff = time.Millisecond
	os.Exit(m.Run())
}

func TestGenerateQualifiesPrefixes(t *testing.T) {
	p := filepath.Join(t.TempDir(), "words.txt")
	body := "# comment\napi\n\nwww\n# another\ndev\n"
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatalf("writing fixture: %s", err)
	}
	got, err := Generate("Example.com", p)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	want := map[string]bool{
		"api.example.com": true, "www.example.com": true, "dev.example.com": true,
	}
	if len(got) != len(want) {
		t.Fatalf("got %v", got)
	}
	for _, g := range got {
		if !want[g] {
			t.Fatalf("unexpected candidate %q", g)
		}
	}
}

func TestGenerateDeduplicates(t *testing.T) {
	p := filepath.Join(t.TempDir(), "words.txt")
	if err := os.WriteFile(p, []byte("api\napi\nAPI\n"), 0o600); err != nil {
		t.Fatalf("writing fixture: %s", err)
	}
	got, err := Generate("example.com", p)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 candidate, got %v", got)
	}
}

func TestGenerateRejectsBadBase(t *testing.T) {
	p := filepath.Join(t.TempDir(), "words.txt")
	_ = os.WriteFile(p, []byte("api\n"), 0o600)
	if _, err := Generate("localhost", p); err == nil {
		t.Fatal("a base without a dot must be rejected")
	}
	if _, err := Generate("", p); err == nil {
		t.Fatal("an empty base must be rejected")
	}
}

func TestGenerateEmptyWordlistErrors(t *testing.T) {
	p := filepath.Join(t.TempDir(), "words.txt")
	_ = os.WriteFile(p, []byte("# nothing here\n"), 0o600)
	if _, err := Generate("example.com", p); err == nil {
		t.Fatal("an empty wordlist must be an error, not an empty scan")
	}
}

func TestGenerateMissingFile(t *testing.T) {
	if _, err := Generate("example.com", "/no/such/file"); err == nil {
		t.Fatal("missing wordlist must error")
	}
}

// ctServer stands in for a certificate transparency service. hit is how many
// times it was queried, which is how the fallback and retry paths are checked.
func ctServer(t *testing.T, hit *int32, handler func(w http.ResponseWriter, r *http.Request)) *PassiveSource {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(hit, 1)
		handler(w, r)
	}))
	t.Cleanup(srv.Close)
	return &PassiveSource{Client: srv.Client(), BaseURL: srv.URL, FallbackURL: srv.URL}
}

func TestPassiveDiscoverParsesCTLog(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("output") != "json" {
			http.Error(w, "want json", http.StatusBadRequest)
			return
		}
		_, _ = w.Write([]byte(`[
			{"common_name":"api.example.com","name_value":"api.example.com\n*.example.com"},
			{"common_name":"shop.example.com","name_value":"shop.example.com"}
		]`))
	}))
	defer srv.Close()

	src := &PassiveSource{Client: srv.Client(), BaseURL: srv.URL}
	got, err := src.Discover(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}

	want := map[string]bool{"api.example.com": true, "shop.example.com": true}
	if len(got) != len(want) {
		t.Fatalf("got %v", got)
	}
	for _, g := range got {
		if !want[g] {
			t.Fatalf("unexpected host %q (wildcard must be trimmed)", g)
		}
	}
	if got[0] > got[1] { // results should be sorted for stable output
		t.Fatalf("results not sorted: %v", got)
	}
}

func TestPassiveDiscoverEmptyResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(""))
	}))
	defer srv.Close()

	src := &PassiveSource{Client: srv.Client(), BaseURL: srv.URL}
	got, err := src.Discover(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("an empty CT result is not an error: %s", err)
	}
	if len(got) != 0 {
		t.Fatalf("got %v", got)
	}
}

func TestPassiveDiscoverRetriesThenFallsBack(t *testing.T) {
	var firstHits, secondHits int32

	// The primary source is rate-limited on the first two attempts and answers
	// on the third, exactly as crt.sh behaves under load.
	primary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&firstHits, 1) < 3 {
			http.Error(w, "rate limited", http.StatusTooManyRequests)
			return
		}
		_, _ = w.Write([]byte(`[{"common_name":"api.example.com","name_value":"api.example.com"}]`))
	}))
	defer primary.Close()

	second := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&secondHits, 1)
		http.Error(w, "nope", http.StatusNotFound)
	}))
	defer second.Close()

	src := &PassiveSource{Client: primary.Client(), BaseURL: primary.URL, FallbackURL: second.URL}
	got, err := src.Discover(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("a transient 429 must be retried, not fatal: %s", err)
	}
	if len(got) != 1 || got[0] != "api.example.com" {
		t.Fatalf("got %v", got)
	}
	if atomic.LoadInt32(&firstHits) < 3 {
		t.Fatalf("expected retries, got %d attempts", firstHits)
	}
	if atomic.LoadInt32(&secondHits) != 0 {
		t.Fatal("fallback must not be used once the primary succeeds")
	}
}

func TestPassiveDiscoverFallsBackWhenPrimaryIsDown(t *testing.T) {
	var primaryHits, secondHits int32

	primary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&primaryHits, 1)
		http.Error(w, "bad gateway", http.StatusBadGateway)
	}))
	defer primary.Close()

	second := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&secondHits, 1)
		_, _ = w.Write([]byte(`[{"dns_names":["shop.example.com","www.example.com"]}]`))
	}))
	defer second.Close()

	src := &PassiveSource{Client: primary.Client(), BaseURL: primary.URL, FallbackURL: second.URL}
	got, err := src.Discover(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("an outage on the primary source must fall through: %s", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %v", got)
	}
	if got[0] != "shop.example.com" {
		t.Fatalf("results not sorted: %v", got)
	}
	if atomic.LoadInt32(&secondHits) == 0 {
		t.Fatal("fallback source was never queried")
	}
}

func TestPassiveDiscoverAllSourcesDown(t *testing.T) {
	var hits int32
	src := ctServer(t, &hits, func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "bad gateway", http.StatusBadGateway)
	})

	_, err := src.Discover(context.Background(), "example.com")
	if err == nil {
		t.Fatal("when every source fails the error must say so")
	}
	for _, want := range []string{"crt.sh", "certspotter", "502"} {
		if !contains(err.Error(), want) {
			t.Errorf("error should mention %q: %s", want, err)
		}
	}
}

func TestPassiveDiscoverDoesNotRetryClientErrors(t *testing.T) {
	var hits int32
	src := ctServer(t, &hits, func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "bad query", http.StatusBadRequest)
	})

	_, err := src.Discover(context.Background(), "example.com")
	if err == nil {
		t.Fatal("HTTP 400 must surface as an error")
	}
	// One attempt per source; a malformed query cannot be fixed by retrying.
	if got := atomic.LoadInt32(&hits); got != 2 {
		t.Fatalf("expected 2 attempts (one per source), got %d", got)
	}
}

func TestPassiveDiscoverIgnoresWildcardOnlyEntries(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`[{"common_name":"*.example.com","name_value":"*.example.com"}]`))
	}))
	defer srv.Close()

	src := &PassiveSource{Client: srv.Client(), BaseURL: srv.URL, FallbackURL: srv.URL}
	got, err := src.Discover(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	if len(got) != 0 {
		t.Fatalf("a wildcard certificate names no specific host: %v", got)
	}
}

func TestPassiveDiscoverRejectsBadBase(t *testing.T) {
	src := &PassiveSource{}
	if _, err := src.Discover(context.Background(), "localhost"); err == nil {
		t.Fatal("base domain must be validated before any request")
	}
}

func TestPassiveDiscoverHonoursContext(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(2 * time.Second)
	}))
	defer srv.Close()

	src := &PassiveSource{Client: srv.Client(), BaseURL: srv.URL}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	if _, err := src.Discover(ctx, "example.com"); err == nil {
		t.Fatal("cancelled context must abort the query")
	}
}

func TestPassiveDiscoverMaxNames(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`[{"common_name":"a.example.com","name_value":"a.example.com"},
			{"common_name":"b.example.com","name_value":"b.example.com"},
			{"common_name":"c.example.com","name_value":"c.example.com"}]`))
	}))
	defer srv.Close()

	src := &PassiveSource{Client: srv.Client(), BaseURL: srv.URL, MaxNames: 2}
	got, err := src.Discover(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	if len(got) != 2 {
		t.Fatalf("MaxNames not applied: %v", got)
	}
}

func TestStreamProcessesEveryItem(t *testing.T) {
	items := make([]string, 500)
	for i := range items {
		items[i] = "host"
	}
	var seen sync.Map
	var count atomic.Int64

	err := Stream(context.Background(), items, 16, func(_ context.Context, s string) error {
		seen.Store(s, true)
		count.Add(1)
		return nil
	})
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	if count.Load() != 500 {
		t.Fatalf("processed %d of 500", count.Load())
	}
}

func TestStreamPropagatesErrorAndStops(t *testing.T) {
	items := make([]string, 1000)
	for i := range items {
		items[i] = "x"
	}
	sentinel := errors.New("boom")
	var calls atomic.Int64

	err := Stream(context.Background(), items, 4, func(context.Context, string) error {
		if calls.Add(1) == 1 {
			return sentinel
		}
		return nil
	})
	if !errors.Is(err, sentinel) {
		t.Fatalf("want sentinel, got %v", err)
	}
	if calls.Load() >= 1000 {
		t.Fatalf("stream did not stop early: %d calls", calls.Load())
	}
}

func TestStreamEmpty(t *testing.T) {
	if err := Stream(context.Background(), nil, 4, func(context.Context, string) error {
		t.Fatal("callback must not run for empty input")
		return nil
	}); err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
}

func TestDefaultWordlistRoundTrip(t *testing.T) {
	p := filepath.Join(t.TempDir(), "words.txt")
	if err := DefaultWordlist(p); err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	got, err := Generate("example.com", p)
	if err != nil {
		t.Fatalf("generated wordlist must be usable: %s", err)
	}
	if len(got) != len(BuiltinPrefixes) {
		t.Fatalf("round trip lost entries: %d vs %d", len(got), len(BuiltinPrefixes))
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(sub) == 0 ||
		func() bool {
			for i := 0; i+len(sub) <= len(s); i++ {
				if s[i:i+len(sub)] == sub {
					return true
				}
			}
			return false
		}())
}
