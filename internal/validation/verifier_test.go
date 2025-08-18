package validation

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/0xStr1k3r/TakeoverX/internal/models"
)

// ── test doubles ─────────────────────────────────────────────────────────────

type stubDNS struct {
	result *models.DNSResult
	second *models.DNSResult
	calls  int
}

func (s *stubDNS) resolve(_ string) *models.DNSResult {
	s.calls++
	if s.calls == 1 || s.second == nil {
		return s.result
	}
	return s.second
}

type stubHTTP struct {
	responses []*models.HTTPResult
	calls     int
}

func (s *stubHTTP) probe(_ context.Context, _ string) *models.HTTPResult {
	s.calls++
	if len(s.responses) == 0 {
		return &models.HTTPResult{Err: "no stub response"}
	}
	if s.calls-1 < len(s.responses) {
		return s.responses[s.calls-1]
	}
	return s.responses[len(s.responses)-1]
}

func bindTestRegistry(t *testing.T) {
	t.Helper()
	s3 := &models.ServiceFingerprint{
		Name: "AWS S3", CNAME: []string{"s3.amazonaws.com"},
		Fingerprints: []string{"NoSuchBucket"}, NXDomain: false, Claimable: true,
		HeaderFingerprints: []string{"AmazonS3"},
		Severity:           "medium", DocsURL: "https://example/s3",
	}
	heroku := &models.ServiceFingerprint{
		Name: "Heroku", CNAME: []string{"herokuapp.com"},
		Fingerprints: []string{"No such app"}, NXDomain: true, Claimable: true,
		Severity: "high", DocsURL: "https://example/heroku",
	}
	cold := &models.ServiceFingerprint{
		Name: "Cloudflare", CNAME: []string{"cloudflare.net"},
		Fingerprints: []string{"cloudflare"},
		Claimable:    false, Severity: "info",
	}
	BindRegistry(
		func(chain []string) (*models.ServiceFingerprint, string) {
			for i := len(chain) - 1; i >= 0; i-- {
				h := strings.ToLower(chain[i])
				if strings.HasSuffix(h, "s3.amazonaws.com") {
					return s3, chain[i]
				}
				if strings.HasSuffix(h, "herokuapp.com") {
					return heroku, chain[i]
				}
				if strings.HasSuffix(h, "cloudflare.net") {
					return cold, chain[i]
				}
			}
			return nil, ""
		},
		func([]string) (*models.ServiceFingerprint, string) { return nil, "" },
		func(fp *models.ServiceFingerprint, body string) (bool, string) {
			for _, f := range fp.Fingerprints {
				if f != "" && body != "" && strings.Contains(body, f) {
					return true, f
				}
			}
			return false, ""
		},
		func(fp *models.ServiceFingerprint, h map[string]string) (bool, string) {
			if v, ok := h["Server"]; ok && strings.Contains(strings.ToLower(v), strings.ToLower(fp.Name)) {
				return true, v
			}
			for _, pattern := range fp.HeaderFingerprints {
				if v, ok := h["Server"]; ok && strings.Contains(strings.ToLower(v), strings.ToLower(pattern)) {
					return true, v
				}
			}
			return false, ""
		},
	)
}

func newTestVerifier(d *stubDNS, h *stubHTTP, wildcard bool, cfg Config) *Verifier {
	if cfg.Repeats == 0 {
		cfg.Repeats = 2
	}
	return &Verifier{
		resolver: d.resolve,
		prober:   h.probe,
		wildcard: func(string) bool { return wildcard },
		cfg:      cfg,
	}
}

// ── tests ────────────────────────────────────────────────────────────────────

func TestHighConfidenceOnRepeatedBodyMatch(t *testing.T) {
	bindTestRegistry(t)
	d := &stubDNS{result: &models.DNSResult{
		Subdomain: "cdn.example.com", RecordType: models.RecordCNAME,
		CNAME: "old-bucket.s3.amazonaws.com", CNAMEChain: []string{"old-bucket.s3.amazonaws.com"},
	}}
	h := &stubHTTP{responses: []*models.HTTPResult{
		{StatusCode: 404, Body: "NoSuchBucket", Headers: map[string]string{"Server": "AmazonS3"}},
		{StatusCode: 404, Body: "NoSuchBucket", Headers: map[string]string{"Server": "AmazonS3"}},
	}}
	v := newTestVerifier(d, h, false, Config{Repeats: 2})

	got := v.Verify(context.Background(), "cdn.example.com", "example.com")

	if got.Status != models.StatusVulnerable {
		t.Fatalf("status: %s (%s)", got.Status, got.Reason)
	}
	if !got.Steps.RepeatConfirmed {
		t.Fatal("repeat confirmation must be recorded")
	}
	if got.Remediation == "" {
		t.Fatal("a finding must carry remediation advice")
	}
	if h.calls < 2 {
		t.Fatalf("expected repeated probes, got %d", h.calls)
	}
}


func TestWildcardDNSDowngradesToUnknown(t *testing.T) {
	bindTestRegistry(t)
	d := &stubDNS{result: &models.DNSResult{
		RecordType: models.RecordCNAME, CNAMEChain: []string{"anything.s3.amazonaws.com"},
	}}
	h := &stubHTTP{responses: []*models.HTTPResult{
		{StatusCode: 404, Body: "NoSuchBucket"},
		{StatusCode: 404, Body: "NoSuchBucket"},
	}}
	v := newTestVerifier(d, h, true, Config{Repeats: 2})

	got := v.Verify(context.Background(), "random.example.com", "example.com")

	if got.Status == models.StatusVulnerable {
		t.Fatal("wildcard DNS must suppress findings — every name resolves")
	}
	if !strings.Contains(got.Reason, "wildcard") {
		t.Fatalf("reason should mention wildcard: %q", got.Reason)
	}
	if h.calls != 0 {
		t.Fatalf("wildcard case should short-circuit before probing, got %d probes", h.calls)
	}
}

func TestDeadCNAMETargetIsHighConfidence(t *testing.T) {
	bindTestRegistry(t)
	d := &stubDNS{result: &models.DNSResult{
		RecordType: models.RecordCNAME,
		CNAME:      "myapp.herokuapp.com", CNAMEChain: []string{"myapp.herokuapp.com"},
		IsDead: true,
	}}
	h := &stubHTTP{responses: []*models.HTTPResult{{Err: "connection refused"}}}
	v := newTestVerifier(d, h, false, Config{Repeats: 2})

	got := v.Verify(context.Background(), "app.example.com", "example.com")

	if got.Status != models.StatusVulnerable {
		t.Fatalf("status: %s (%s)", got.Status, got.Reason)
	}
}

func TestDeadTargetOnNonNXDOMAINProviderStaysUnknown(t *testing.T) {
	bindTestRegistry(t)
	d := &stubDNS{result: &models.DNSResult{
		RecordType: models.RecordCNAME,
		CNAME:      "x.s3.amazonaws.com", CNAMEChain: []string{"x.s3.amazonaws.com"},
		IsDead: true,
	}}
	h := &stubHTTP{responses: []*models.HTTPResult{{Err: "timeout"}}}
	v := newTestVerifier(d, h, false, Config{Repeats: 2})

	got := v.Verify(context.Background(), "x.example.com", "example.com")

	if got.Status == models.StatusVulnerable {
		t.Fatal("a dead target only proves a takeover for nxdomain providers")
	}
}

func TestServedContentIsSafe(t *testing.T) {
	bindTestRegistry(t)
	d := &stubDNS{result: &models.DNSResult{
		RecordType: models.RecordCNAME, CNAMEChain: []string{"live.s3.amazonaws.com"},
	}}
	h := &stubHTTP{responses: []*models.HTTPResult{
		{StatusCode: 200, Body: "<html>the real site</html>"},
		{StatusCode: 200, Body: "<html>the real site</html>"},
	}}
	v := newTestVerifier(d, h, false, Config{Repeats: 2})

	got := v.Verify(context.Background(), "live.example.com", "example.com")

	if got.Status != models.StatusSafe {
		t.Fatalf("status: %s (%s)", got.Status, got.Reason)
	}
	if !strings.Contains(got.Reason, "claimed") {
		t.Fatalf("reason should say the resource is claimed: %q", got.Reason)
	}
}

func TestUnknownProviderIsSafe(t *testing.T) {
	bindTestRegistry(t)
	d := &stubDNS{result: &models.DNSResult{
		RecordType: models.RecordA, IPs: []string{"1.2.3.4"},
	}}
	h := &stubHTTP{responses: []*models.HTTPResult{{StatusCode: 200}}}
	v := newTestVerifier(d, h, false, Config{Repeats: 1})

	got := v.Verify(context.Background(), "plain.example.com", "example.com")

	if got.Status != models.StatusSafe {
		t.Fatalf("status: %s", got.Status)
	}
	if h.calls != 0 {
		t.Fatal("no provider means no reason to probe")
	}
}



func TestBodyMatchStillWinsForClaimableProvider(t *testing.T) {
	// The correction must not weaken real detections.
	bindTestRegistry(t)
	d := &stubDNS{result: &models.DNSResult{
		RecordType: models.RecordCNAME, CNAMEChain: []string{"gone.s3.amazonaws.com"},
	}}
	h := &stubHTTP{responses: []*models.HTTPResult{
		{StatusCode: 404, Body: "NoSuchBucket"},
		{StatusCode: 404, Body: "NoSuchBucket"},
	}}
	v := newTestVerifier(d, h, false, Config{Repeats: 2, TrustHeaders: true})

	got := v.Verify(context.Background(), "cdn.example.com", "example.com")
	if got.Status != models.StatusVulnerable {
		t.Fatalf("a genuine unclaimed response must still be reported: %s (%s)", got.Status, got.Reason)
	}
}


func TestSkipVerifyReturnsUnknownNotVulnerable(t *testing.T) {
	bindTestRegistry(t)
	d := &stubDNS{result: &models.DNSResult{
		RecordType: models.RecordCNAME, CNAMEChain: []string{"b.s3.amazonaws.com"},
	}}
	h := &stubHTTP{}
	v := newTestVerifier(d, h, false, Config{SkipVerify: true})

	got := v.Verify(context.Background(), "x.example.com", "")

	if got.Status != models.StatusUnknown {
		t.Fatalf("skipped verification must be UNKNOWN, got %s", got.Status)
	}
	if got.Service == nil {
		t.Fatal("provider should still be named")
	}
}

func TestUnboundRegistryDoesNotPanic(t *testing.T) {
	BindRegistry(nil, nil, nil, nil)
	d := &stubDNS{result: &models.DNSResult{RecordType: models.RecordA, IPs: []string{"1.2.3.4"}}}
	h := &stubHTTP{}
	v := newTestVerifier(d, h, false, Config{Repeats: 1})

	got := v.Verify(context.Background(), "x.example.com", "")
	if got.Status != models.StatusSafe {
		t.Fatalf("status: %s", got.Status)
	}
}

func TestVerifyRespectsContextCancellation(t *testing.T) {
	bindTestRegistry(t)
	d := &stubDNS{result: &models.DNSResult{
		RecordType: models.RecordCNAME, CNAMEChain: []string{"b.s3.amazonaws.com"},
	}}
	h := &stubHTTP{responses: []*models.HTTPResult{{StatusCode: 404, Body: "NoSuchBucket"}}}
	v := newTestVerifier(d, h, false, Config{Repeats: 5, RepeatDelay: time.Hour})

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	done := make(chan struct{})
	go func() {
		v.Verify(ctx, "slow.example.com", "example.com")
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Verify ignored context cancellation")
	}
}

func TestStepsPassedIsReadable(t *testing.T) {
	s := Steps{ProviderFound: true, NotWildcard: true, RepeatConfirmed: true, BodyMatched: false}
	got := s.Passed()
	if len(got) != 3 {
		t.Fatalf("expected 3 passed steps, got %v", got)
	}
	for _, g := range got {
		if g == "" {
			t.Fatal("empty step description")
		}
	}
}

func TestDefaultWildcardBase(t *testing.T) {
	cases := map[string]string{
		"a.b.example.com":        "example.com",
		"example.com":            "example.com",
		"a.b.example.co.uk":      "example.co.uk",
		"deep.a.b.c.example.com": "example.com",
	}
	for in, want := range cases {
		if got := DefaultWildcardBase(in); got != want {
			t.Errorf("DefaultWildcardBase(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestNoPanicOnEmptyResponse(t *testing.T) {
	bindTestRegistry(t)
	d := &stubDNS{result: &models.DNSResult{
		RecordType: models.RecordCNAME, CNAMEChain: []string{"b.s3.amazonaws.com"},
	}}
	h := &stubHTTP{responses: []*models.HTTPResult{{Err: "boom"}}}
	v := newTestVerifier(d, h, false, Config{Repeats: 1})

	got := v.Verify(context.Background(), "x.example.com", "example.com")
	if got.Status == models.StatusVulnerable {
		t.Fatal("probe failure must not produce a finding")
	}
}
