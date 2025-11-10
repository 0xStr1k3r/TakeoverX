package validation

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/0xStr1k3r/TakeoverX/internal/httpclient"
	"github.com/0xStr1k3r/TakeoverX/internal/models"
)

// TestEndToEndAgainstRealServer drives the full pipeline against a live HTTP
// server rather than a stubbed probe, so the request/response path, the
// redirect policy and the body reader are all exercised together.
func TestEndToEndAgainstRealServer(t *testing.T) {
	bindTestRegistry(t)
	var hits atomic.Int64

	unclaimed := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("Server", "AmazonS3")
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?>
<Error><Code>NoSuchBucket</Code><Message>The specified bucket does not exist</Message></Error>`))
	}))
	defer unclaimed.Close()

	host := strings.TrimPrefix(unclaimed.URL, "http://")

	dnsResult := &models.DNSResult{
		Subdomain: host, RecordType: models.RecordCNAME,
		CNAME: "gone.s3.amazonaws.com", CNAMEChain: []string{"gone.s3.amazonaws.com"},
	}

	verifier := newLiveVerifier(t, dnsResult)
	got := verifier.Verify(context.Background(), host, "")

	if got.Status != models.StatusVulnerable {
		t.Fatalf("a live NoSuchBucket response must be a finding: %s (%s)", got.Status, got.Reason)
	}
	if got.Confidence != models.ConfidenceHigh {
		t.Fatalf("confidence: %s", got.Confidence)
	}
	if !strings.Contains(got.Reason, "unclaimed") {
		t.Fatalf("reason should name the evidence: %q", got.Reason)
	}
	if got.Remediation == "" {
		t.Fatal("a finding must tell the operator what to do")
	}
	if hits.Load() < 2 {
		t.Fatalf("expected the probe to be repeated for confirmation, got %d request(s)", hits.Load())
	}
}

func TestEndToEndServingSiteIsSafe(t *testing.T) {
	bindTestRegistry(t)
	live := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "AmazonS3")
		_, _ = w.Write([]byte("<html><body>The real site is here</body></html>"))
	}))
	defer live.Close()

	host := strings.TrimPrefix(live.URL, "http://")
	dnsResult := &models.DNSResult{
		Subdomain: host, RecordType: models.RecordCNAME,
		CNAME: "live.s3.amazonaws.com", CNAMEChain: []string{"live.s3.amazonaws.com"},
	}

	verifier := newLiveVerifier(t, dnsResult)
	got := verifier.Verify(context.Background(), host, "")

	if got.Status != models.StatusSafe {
		t.Fatalf("a site that serves its own content is claimed, got %s (%s)", got.Status, got.Reason)
	}
}

func TestEndToEndRedirectToHealthPageIsNotAFinding(t *testing.T) {
	bindTestRegistry(t)
	// A trailing slash redirect is ordinary, not a takeover signal.
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, r.URL.Path+"app/", http.StatusFound)
	})
	mux.HandleFunc("/app/", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("<html>healthy</html>"))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	host := strings.TrimPrefix(srv.URL, "http://")
	dnsResult := &models.DNSResult{
		Subdomain: host, RecordType: models.RecordCNAME,
		CNAME: "app.s3.amazonaws.com", CNAMEChain: []string{"app.s3.amazonaws.com"},
	}

	verifier := newLiveVerifier(t, dnsResult)
	got := verifier.Verify(context.Background(), host, "")

	if got.Status == models.StatusVulnerable {
		t.Fatal("a redirect must never be reported as a takeover")
	}
}

// newLiveVerifier wires the real HTTP client to a stubbed DNS layer.
func newLiveVerifier(t *testing.T, d *models.DNSResult) *Verifier {
	t.Helper()
	client := httpclient.New(5*time.Second, 0, "")
	t.Cleanup(client.CloseIdle)

	return &Verifier{
		// A stable answer on every call, so the DNS re-check passes and the
		// test isolates the HTTP evidence.
		resolver: func(string) *models.DNSResult { return d },
		prober:   client.Probe,
		wildcard: func(string) bool { return false },
		cfg:      Config{Repeats: 2, RepeatDelay: 5 * time.Millisecond, TrustHeaders: true},
	}
}
