package cmd

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/0xStr1k3r/TakeoverX/internal/dns"
	"github.com/0xStr1k3r/TakeoverX/internal/httpclient"
	"github.com/0xStr1k3r/TakeoverX/internal/models"
	"github.com/0xStr1k3r/TakeoverX/internal/validation"
)

func resetOpts(t *testing.T) {
	t.Helper()
	saved := opts
	t.Cleanup(func() { opts = saved })
	opts = options{
		concurrent: 10, timeout: 5, repeats: 1,
		out: "table", failOn: "medium", proxy: "",
	}
}

func TestValidateFlags(t *testing.T) {
	cases := []struct {
		name string
		set  func(*options)
		ok   bool
		want string
	}{
		{"nothing given", func(o *options) {}, false, "nothing to scan"},
		{"domain", func(o *options) { o.domain = "example.com" }, true, ""},
		{"wordlist", func(o *options) { o.wordlist = "w.txt" }, true, ""},
		{"stdin", func(o *options) { o.stdin = true }, true, ""},
		{"bruteforce without domain", func(o *options) { o.bruteforce = "w.txt" }, false, "-b needs a base domain"},
		{"passive without domain", func(o *options) { o.passive = true }, false, "--passive needs a base domain"},
		{"bad format", func(o *options) { o.domain = "e.com"; o.out = "xml" }, false, "unknown -o format"},
		{"bad fail-on", func(o *options) { o.domain = "e.com"; o.failOn = "nope" }, false, "--fail-on"},
		{"bad proxy", func(o *options) { o.domain = "e.com"; o.proxy = "garbage" }, false, "--proxy"},
		{"zero workers", func(o *options) { o.domain = "e.com"; o.concurrent = 0 }, false, "-c must be at least 1"},
		{"zero timeout", func(o *options) { o.domain = "e.com"; o.timeout = 0 }, false, "--timeout"},
		{"zero repeats", func(o *options) { o.domain = "e.com"; o.repeats = 0 }, false, "--repeats"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			resetOpts(t)
			c.set(&opts)
			err := validateFlags()
			if c.ok && err != nil {
				t.Fatalf("expected success, got %s", err)
			}
			if !c.ok {
				if err == nil {
					t.Fatal("expected an error")
				}
				if !strings.Contains(err.Error(), c.want) {
					t.Fatalf("error %q does not mention %q", err, c.want)
				}
			}
		})
	}
}

func TestConfidenceAtLeast(t *testing.T) {
	cases := []struct {
		got, threshold string
		want           bool
	}{
		{"HIGH", "high", true},
		{"HIGH", "medium", true},
		{"MEDIUM", "high", false},
		{"MEDIUM", "medium", true},
		{"MEDIUM", "low", true},
		{"LOW", "medium", false},
		{"LOW", "low", true},
		{"", "medium", false},
		{"garbage", "medium", false},
		{"HIGH", "medium", true},
	}
	for _, c := range cases {
		if got := confidenceAtLeast(c.got, c.threshold); got != c.want {
			t.Errorf("confidenceAtLeast(%q,%q) = %v, want %v", c.got, c.threshold, got, c.want)
		}
	}
}

func TestToScanResultCarriesEverything(t *testing.T) {
	bindFakeRegistry()
	res := validation.Result{
		Subdomain:   "shop.example.com",
		Status:      models.StatusVulnerable,
		Confidence:  models.ConfidenceHigh,
		Service:     &models.ServiceFingerprint{Name: "Shopify", Severity: "critical"},
		Reason:      "unclaimed",
		Remediation: "remove the record",
		DocsURL:     "https://example/docs",
		MatchedBy:   "shop.myshopify.com",
		Duration:    1500 * time.Millisecond,
		Steps:       validation.Steps{ProviderFound: true, BodyMatched: true},
	}
	got := toScanResult(res)

	if got.Subdomain != "shop.example.com" {
		t.Fatalf("subdomain: %s", got.Subdomain)
	}
	if got.Status != "VULNERABLE" {
		t.Fatalf("status: %s", got.Status)
	}
	if got.Service != "Shopify" {
		t.Fatalf("service: %s", got.Service)
	}
	if got.Severity != "critical" {
		t.Fatalf("severity: %s", got.Severity)
	}
	if len(got.Steps) != 2 {
		t.Fatalf("steps not carried over: %v", got.Steps)
	}
	if got.Steps[0] != "provider identified from DNS" {
		t.Fatalf("unexpected step text: %q", got.Steps[0])
	}
	if got.Duration < 1500 {
		t.Fatalf("duration: %v", got.Duration)
	}
}

func TestToScanResultWithNoService(t *testing.T) {
	got := toScanResult(validation.Result{Subdomain: "x.example.com", Status: models.StatusSafe})
	if got.Service != "" {
		t.Fatalf("service should be empty, got %q", got.Service)
	}
	if got.RecordType != "" {
		t.Fatalf("record type should be empty, got %q", got.RecordType)
	}
}

func TestWildcardCacheMemoises(t *testing.T) {
	calls := 0
	wc := newWildcardCache(func(string) bool {
		calls++
		return true
	})
	for i := 0; i < 50; i++ {
		if !wc.isWildcard("example.com") {
			t.Fatal("expected wildcard")
		}
	}
	if calls != 1 {
		t.Fatalf("zone probed %d times, want 1", calls)
	}
}

func TestWildcardCacheSeparateZones(t *testing.T) {
	calls := map[string]int{}
	wc := newWildcardCache(func(base string) bool {
		calls[base]++
		return base == "wild.example.com"
	})
	if !wc.isWildcard("wild.example.com") {
		t.Fatal("expected wildcard for wild zone")
	}
	if wc.isWildcard("clean.example.com") {
		t.Fatal("did not expect wildcard for clean zone")
	}
	wc.isWildcard("wild.example.com")
	wc.isWildcard("clean.example.com")
	if calls["wild.example.com"] != 1 || calls["clean.example.com"] != 1 {
		t.Fatalf("each zone must be probed once: %v", calls)
	}
}

func TestWildcardCacheIgnoresBlankBase(t *testing.T) {
	probed := false
	wc := newWildcardCache(func(string) bool { probed = true; return true })
	if wc.isWildcard("") || wc.isWildcard("localhost") {
		t.Fatal("blank or dotless base must never be probed")
	}
	if probed {
		t.Fatal("probe should not have happened")
	}
}

func TestWildcardCacheIsConcurrencySafe(t *testing.T) {
	var mu = make(chan struct{}, 1)
	mu <- struct{}{}
	calls := 0
	wc := newWildcardCache(func(string) bool {
		<-mu
		calls++
		mu <- struct{}{}
		return false
	})
	done := make(chan struct{})
	for i := 0; i < 20; i++ {
		go func() {
			defer func() { done <- struct{}{} }()
			for j := 0; j < 50; j++ {
				wc.isWildcard("example.com")
			}
		}()
	}
	for i := 0; i < 20; i++ {
		<-done
	}
	close(done)
	if calls != 1 {
		t.Fatalf("concurrent access probed %d times", calls)
	}
}

func TestMergeUnique(t *testing.T) {
	got := mergeUnique([]string{"a.com", "b.com"}, []string{"b.com", "c.com", ""})
	want := []string{"a.com", "b.com", "c.com"}
	if len(got) != len(want) {
		t.Fatalf("got %v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
}

func TestMergeUniqueDoesNotMutateInputs(t *testing.T) {
	a := []string{"a.com"}
	b := []string{"b.com"}
	mergeUnique(a, b)
	if len(a) != 1 || len(b) != 1 {
		t.Fatal("mergeUnique mutated its inputs")
	}
}

func TestRateLabel(t *testing.T) {
	resetOpts(t)
	opts.rate = 0
	if got := rateLabel(); got != "unlimited" {
		t.Fatalf("got %q", got)
	}
	opts.rate = 25
	if got := rateLabel(); got != "25/s" {
		t.Fatalf("got %q", got)
	}
}

func TestTargetLabel(t *testing.T) {
	resetOpts(t)
	opts.domain = "example.com"
	if got := targetLabel([]string{"a"}, "list"); got != "example.com" {
		t.Fatalf("got %q", got)
	}
	opts.domain = ""
	if got := targetLabel([]string{"a"}, "list+passive"); got != "1 hostnames" {
		t.Fatalf("got %q", got)
	}
}

func TestDefaultReportPath(t *testing.T) {
	if got := defaultReportPath("custom.html", "report.html"); got != "custom.html" {
		t.Fatalf("got %q", got)
	}
	if got := defaultReportPath("", "report.html"); got != "report.html" {
		t.Fatalf("got %q", got)
	}
}

// cnameResolver answers every name with a CNAME the stub registry recognises,
// so verification reaches the wildcard gate instead of returning early.
type cnameResolver struct{}

func (cnameResolver) LookupCNAME(_ context.Context, host string) (string, error) {
	if host == "example.com" {
		return host, nil
	}
	return "gone.myshopify.com.", nil
}
func (cnameResolver) LookupHost(_ context.Context, host string) ([]string, error) {
	return []string{"203.0.113.10"}, nil
}

func withCNAMEResolver(t *testing.T) {
	t.Helper()
	old := dns.DefaultResolverForTest()
	dns.SetResolver(cnameResolver{})
	dns.ResetCache()
	t.Cleanup(func() { dns.SetResolver(old); dns.ResetCache() })
}

func TestWildcardProbeIsSkippedWhenVerificationIsOff(t *testing.T) {
	// --no-verify promises to skip verification work. The wildcard probe is two
	// DNS queries per zone, so honouring that matters on a large bruteforce.
	bindFakeRegistry()
	withCNAMEResolver(t)

	probes := 0
	wc := newWildcardCache(func(string) bool { probes++; return false })

	client := httpclient.New(time.Second, 0, "")
	defer client.CloseIdle()

	cfg := validation.DefaultConfig()
	cfg.SkipVerify = true
	v := validation.New(client, cfg)
	v.SetWildcardCheck(wc.isWildcard)

	for i := 0; i < 5; i++ {
		v.Verify(context.Background(), fmt.Sprintf("h%d.example.com", i), "example.com")
	}
	if probes != 0 {
		t.Fatalf("--no-verify performed %d wildcard probe(s)", probes)
	}
}

func TestWildcardCheckIsInjectedIntoTheVerifier(t *testing.T) {
	bindFakeRegistry()
	withCNAMEResolver(t)

	probes := 0
	wc := newWildcardCache(func(string) bool { probes++; return true })

	client := httpclient.New(time.Second, 0, "")
	defer client.CloseIdle()

	cfg := validation.DefaultConfig()
	cfg.Repeats = 1
	v := validation.New(client, cfg)
	v.SetWildcardCheck(wc.isWildcard)

	for i := 0; i < 20; i++ {
		v.Verify(context.Background(), fmt.Sprintf("h%d.example.com", i), "example.com")
	}
	if probes != 1 {
		t.Fatalf("one zone should be probed once across 20 hosts, got %d", probes)
	}
}

func TestWildcardCacheSingleFlightsOneProbe(t *testing.T) {
	// A hundred workers arriving at the same uncached zone must not each start
	// their own probe.
	release := make(chan struct{})
	entered := make(chan struct{}, 64)
	wc := newWildcardCache(func(string) bool {
		entered <- struct{}{}
		<-release
		return true
	})

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if !wc.isWildcard("example.com") {
				t.Error("expected wildcard")
			}
		}()
	}

	<-entered // the first probe is running
	// Give the rest of the workers time to pile up on the same key.
	time.Sleep(50 * time.Millisecond)
	close(release)
	wg.Wait()

	select {
	case <-entered:
		t.Fatal("more than one probe ran for the same zone")
	default:
	}
}

func TestContainsString(t *testing.T) {
	if !containsString([]string{"a", "b"}, "b") {
		t.Fatal("expected true")
	}
	if containsString([]string{"a", "b"}, "z") {
		t.Fatal("expected false")
	}
}

// bindFakeRegistry installs a minimal registry so toScanResult and verify have
// something to work with.
func bindFakeRegistry() {
	fp := &models.ServiceFingerprint{Name: "Shopify", CNAME: []string{"myshopify.com"}, Claimable: true}
	validation.BindRegistry(
		func(chain []string) (*models.ServiceFingerprint, string) {
			for _, h := range chain {
				if strings.Contains(h, "myshopify.com") {
					return fp, h
				}
			}
			return nil, ""
		},
		func([]string) (*models.ServiceFingerprint, string) { return nil, "" },
		func(f *models.ServiceFingerprint, body string) (bool, string) {
			return strings.Contains(body, "unavailable"), "unavailable"
		},
		func(*models.ServiceFingerprint, map[string]string) (bool, string) { return false, "" },
	)
}
