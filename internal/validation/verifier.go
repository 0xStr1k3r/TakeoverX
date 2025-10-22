package validation

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/0xStr1k3r/TakeoverX/internal/dns"
	"github.com/0xStr1k3r/TakeoverX/internal/httpclient"
	"github.com/0xStr1k3r/TakeoverX/internal/models"
)

// Steps records which evidence gates passed, so a result can be audited instead
// of trusted. Order is the order the gates are evaluated in.
type Steps struct {
	ProviderFound   bool `json:"provider_found"`
	NotWildcard     bool `json:"not_wildcard"`
	DNSCached       bool `json:"dns_cached"`
	DeadTarget      bool `json:"dead_target"`
	BodyMatched     bool `json:"body_matched"`
	HeaderMatched   bool `json:"header_matched"`
	RepeatConfirmed bool `json:"repeat_confirmed"`
	RecheckStable   bool `json:"recheck_stable"`
}

// Passed returns the human-readable gates that succeeded, for --explain.
func (s Steps) Passed() []string {
	var out []string
	add := func(ok bool, name string) {
		if ok {
			out = append(out, name)
		}
	}
	add(s.ProviderFound, "provider identified from DNS")
	add(s.NotWildcard, "zone has no wildcard DNS")
	add(s.DeadTarget, "CNAME target no longer resolves")
	add(s.BodyMatched, "provider fingerprint in response body")
	add(s.HeaderMatched, "provider signature in response header")
	add(s.RepeatConfirmed, "fingerprint stable across repeated probes")
	add(s.RecheckStable, "DNS answer stable on re-resolution")
	return out
}

// Config tunes the verification pipeline.
type Config struct {
	Repeats      int           // independent probes that must agree (>=1)
	RepeatDelay  time.Duration // pause between repeats
	RecheckDNS   bool          // re-resolve after HTTP to catch flapping records
	TrustHeaders bool          // allow header-only matches
	SkipVerify   bool          // report the raw CNAME match without probing
}

// DefaultConfig is the accuracy-first preset used unless -n is passed.
func DefaultConfig() Config {
	return Config{Repeats: 2, RepeatDelay: 250 * time.Millisecond, RecheckDNS: true, TrustHeaders: true}
}

// Result carries the verdict plus every gate that produced it.
type Result struct {
	Subdomain   string
	Status      models.Status
	Confidence  models.Confidence
	Service     *models.ServiceFingerprint
	MatchedBy   string
	Reason      string
	Remediation string
	DocsURL     string
	Severity    string
	Steps       Steps
	Duration    time.Duration
}

// Verifier runs the multi-step pipeline. The DNS and HTTP collaborators are
// injectable so tests never touch the network.
type Verifier struct {
	resolver   func(string) *models.DNSResult
	prober     func(context.Context, string) *models.HTTPResult
	wildcard   func(string) bool
	cfg        Config
	repeatsOut int
}

// New builds a Verifier with the real resolver and an HTTP client.
func New(client *httpclient.Client, cfg Config) *Verifier {
	if cfg.Repeats < 1 {
		cfg.Repeats = 1
	}
	return &Verifier{
		resolver: dns.Resolve,
		prober: func(ctx context.Context, host string) *models.HTTPResult {
			return client.Probe(ctx, host)
		},
		wildcard: dns.WildcardActive,
		cfg:      cfg,
	}
}

// SetWildcardCheck replaces the wildcard-DNS probe. The caller passes a
// memoising wrapper so that a zone is probed once per scan rather than once per
// hostname, and so the probe is skipped entirely when verification is off.
func (v *Verifier) SetWildcardCheck(fn func(string) bool) {
	if fn != nil {
		v.wildcard = fn
	}
}

// Verify evaluates one subdomain end to end and returns a scored verdict.
//
// The pipeline is deliberately ordered cheapest-first and strongest-last:
//
//  1. resolve DNS and identify the provider (a CNAME match alone is not a
//     finding — it is only a lead);
//  2. rule out wildcard DNS, which makes every name "resolve" and invalidates
//     step 1;
//  3. probe over HTTP and look for the provider's own unclaimed-resource
//     response in the body, then the headers;
//  4. treat a dead (NXDOMAIN) CNAME target as evidence for providers whose
//     takeover manifests that way;
//  5. repeat the probe and re-resolve so a one-off network error or a
//     flapping record cannot produce a finding.
func (v *Verifier) Verify(ctx context.Context, host string, wildcardBase string) Result {
	start := time.Now()
	res := Result{Subdomain: host, Status: models.StatusSafe, Confidence: models.ConfidenceLow}

	d := v.resolver(host)
	res.Steps.DNSCached = dns.CachedCount() > 0

	// ── Step 1: find the provider ────────────────────────────────────────────
	var svc *models.ServiceFingerprint
	matchedBy := ""
	if registryDetect == nil {
		res.Reason = "service registry not initialised"
		res.Duration = time.Since(start)
		return res
	}
	if d.RecordType == models.RecordCNAME && len(d.CNAMEChain) > 0 {
		svc, matchedBy = registryDetect(d.CNAMEChain)
	} else if len(d.IPs) > 0 && d.RecordType != models.RecordNone {
		svc, matchedBy = registryDetectIP(d.IPs)
	}

	if svc == nil {
		res.Status = models.StatusSafe
		if d.NXDomain || d.RecordType == models.RecordNone {
			res.Reason = "no DNS record"
		} else {
			res.Reason = "DNS does not point at a known cloud service"
		}
		res.Duration = time.Since(start)
		return res
	}
	res.Service = svc
	res.Steps.ProviderFound = true
	res.MatchedBy = matchedBy
	res.DocsURL = svc.DocsURL
	res.Severity = svc.Severity

	if v.cfg.SkipVerify {
		res.Status = models.StatusUnknown
		res.Confidence = models.ConfidenceLow
		res.Reason = fmt.Sprintf("DNS points at %s (verification skipped)", svc.Name)
		res.Remediation = fmt.Sprintf("Confirm manually that %s no longer serves this name.", svc.Name)
		res.Duration = time.Since(start)
		return res
	}

	// ── Step 2: wildcard DNS veto ────────────────────────────────────────────
	if wildcardBase != "" && v.wildcard(wildcardBase) {
		res.Steps.NotWildcard = false
		res.Status = models.StatusUnknown
		res.Confidence = models.ConfidenceLow
		res.Reason = fmt.Sprintf("%s publishes wildcard DNS, so CNAME matching is unreliable here", wildcardBase)
		res.Remediation = "Disable wildcard DNS for this zone, then re-scan."
		res.Duration = time.Since(start)
		return res
	}
	res.Steps.NotWildcard = true

	// ── Step 3/5: probe, then confirm the match repeats ─────────────────────
	ctx, cancel := context.WithTimeout(ctx, 40*time.Second)
	defer cancel()

	probe := v.prober(ctx, host)
	bodyMatch, bodyFP := false, ""
	headerMatch, headerFP := false, ""
	if probe.Err == "" {
		bodyMatch, bodyFP = bodyFingerprint(svc, probe.Body)
		headerMatch, headerFP = headerFingerprint(svc, probe.Headers)
	}
	res.Steps.BodyMatched = bodyMatch
	res.Steps.HeaderMatched = headerMatch && v.cfg.TrustHeaders
	res.Steps.DeadTarget = d.IsDead

	confirmed := false
	if bodyMatch || (headerMatch && v.cfg.TrustHeaders) {
		confirmed = v.reconfirm(ctx, host, svc, bodyMatch)
	}
	res.Steps.RepeatConfirmed = confirmed

	// ── Step 6: DNS stability ───────────────────────────────────────────────
	if v.cfg.RecheckDNS {
		dns.ResetCache()
		again := v.resolver(host)
		res.Steps.RecheckStable = sameTarget(d, again)
	} else {
		res.Steps.RecheckStable = true
	}

	// ── Verdict ─────────────────────────────────────────────────────────────
	//
	// A finding requires positive evidence that the resource is UNCLAIMED.
	// Two things that look like evidence are not:
	//
	//   - The DNS pointing at a provider. That is the normal, correct state of
	//     a working deployment.
	//   - A provider signature in a response header. "Server: cloudfront" is
	//     present on every healthy CloudFront site in the world; it identifies
	//     the provider in the path, not the state of the resource. OWASP is
	//     explicit that dangling DNS alone does not establish claimability,
	//     because AWS requires a matching certificate before it will attach an
	//     alternate domain name to a distribution.
	//
	// So the only routes to VULNERABLE are the provider's own "this is not
	// yours" page, or a target that has stopped existing for a provider whose
	// takeover manifests that way.
	switch {
	case bodyMatch && confirmed && res.Steps.RecheckStable:
		res.Status = models.StatusVulnerable
		res.Confidence = models.ConfidenceHigh
		res.Reason = fmt.Sprintf("%s reports the resource is unclaimed (%q)", svc.Name, bodyFP)
		res.Remediation = fmt.Sprintf("Remove the dangling %s record, or claim the resource in the %s console.", strings.ToUpper(string(d.RecordType)), svc.Name)

	case bodyMatch && !confirmed:
		res.Status = models.StatusUnknown
		res.Confidence = models.ConfidenceLow
		res.Reason = fmt.Sprintf("%s fingerprint seen once but not on repeat probe — treating as a network artefact", svc.Name)

	case d.IsDead && svc.NXDomain:
		res.Status = models.StatusVulnerable
		res.Confidence = models.ConfidenceHigh
		res.Reason = fmt.Sprintf("%s target no longer resolves, so the name is claimable", svc.Name)
		res.Remediation = fmt.Sprintf("Remove the %s record or claim the resource at %s.", strings.ToUpper(string(d.RecordType)), svc.DocsURL)

	case d.IsDead:
		res.Status = models.StatusUnknown
		res.Confidence = models.ConfidenceMedium
		res.Reason = fmt.Sprintf("%s target does not resolve; provider takeover is not implied", svc.Name)

	case res.Steps.ProviderFound && probe.Err != "":
		res.Status = models.StatusUnknown
		res.Confidence = models.ConfidenceLow
		res.Reason = fmt.Sprintf("DNS points at %s but the HTTP probe failed: %s", svc.Name, probe.Err)

	default:
		// The probe reached the provider and none of its unclaimed
		// fingerprints appeared, so there is no positive evidence of a
		// takeover. A provider signature is noted but never decides this: it
		// says who is in the path, not whether the resource is claimed.
		res.Confidence = models.ConfidenceLow
		switch {
		case headerMatch:
			// A provider signature says who is in the path, not whether the
			// resource is claimed, so it cannot decide the verdict.
			res.Status = models.StatusUnknown
			res.Reason = fmt.Sprintf("%s is in the request path (%q), which does not show the resource is unclaimed", svc.Name, headerFP)
			res.Remediation = "Open the URL and confirm the provider still lists this name as yours."
		case probe.StatusCode >= 400:
			// An error page we do not recognise is exactly the shape of a
			// dangling record pointing at a provider that is missing from the
			// fingerprint database. Surfacing it as inconclusive is far more
			// useful than reporting it as safe.
			res.Status = models.StatusUnknown
			res.Reason = fmt.Sprintf("%s answered HTTP %d with no known unclaimed fingerprint — worth checking by hand", svc.Name, probe.StatusCode)
			res.Remediation = "Open the URL and confirm the provider still lists this name as yours."
		default:
			res.Status = models.StatusSafe
			res.Reason = fmt.Sprintf("%s is serving content, so the resource is claimed", svc.Name)
		}
	}

	res.Duration = time.Since(start)
	return res
}

// reconfirm probes repeatedly; every probe must reproduce the original
// evidence. A single differing response means the match was transient.
func (v *Verifier) reconfirm(ctx context.Context, host string, svc *models.ServiceFingerprint, wantBody bool) bool {
	for i := 1; i < v.cfg.Repeats; i++ {
		select {
		case <-ctx.Done():
			return false
		case <-time.After(v.cfg.RepeatDelay):
		}
		p := v.prober(ctx, host)
		if p.Err != "" {
			return false
		}
		if wantBody {
			if ok, _ := bodyFingerprint(svc, p.Body); !ok {
				return false
			}
			continue
		}
		ok, _ := headerFingerprint(svc, p.Headers)
		if !ok {
			return false
		}
	}
	return true
}

// sameTarget reports whether two resolutions agree on the terminal target.
func sameTarget(a, b *models.DNSResult) bool {
	if a.RecordType != b.RecordType {
		return false
	}
	if len(a.CNAMEChain) == 0 && len(b.CNAMEChain) == 0 {
		return true
	}
	if len(a.CNAMEChain) == 0 || len(b.CNAMEChain) == 0 {
		return false
	}
	return strings.EqualFold(a.CNAMEChain[len(a.CNAMEChain)-1], b.CNAMEChain[len(b.CNAMEChain)-1])
}

// The registry is installed once at startup by services.SetRegistry.
var (
	registryDetect    func(chain []string) (*models.ServiceFingerprint, string)
	registryDetectIP  func(ips []string) (*models.ServiceFingerprint, string)
	bodyFingerprint   func(fp *models.ServiceFingerprint, body string) (bool, string)
	headerFingerprint func(fp *models.ServiceFingerprint, h map[string]string) (bool, string)
)

// BindRegistry wires the service registry and matcher into the verifier,
// avoiding an import cycle between services and validation.
func BindRegistry(
	detect func([]string) (*models.ServiceFingerprint, string),
	detectIP func([]string) (*models.ServiceFingerprint, string),
	matchBody func(*models.ServiceFingerprint, string) (bool, string),
	matchHeader func(*models.ServiceFingerprint, map[string]string) (bool, string),
) {
	registryDetect = detect
	registryDetectIP = detectIP
	bodyFingerprint = matchBody
	headerFingerprint = matchHeader
}

// DefaultWildcardBase derives the zone to wildcard-probe from a subdomain:
// the registrable domain, i.e. the public suffix plus one more label. A wildcard
// on that zone is what invalidates CNAME matching for every name beneath it.
func DefaultWildcardBase(host string) string {
	host = models.NormalizeDomain(host)
	parts := strings.Split(host, ".")
	if len(parts) < 3 {
		return host
	}
	labels := 2
	if isSecondLevelSuffix(parts[len(parts)-2]) {
		labels = 3
	}
	if len(parts) <= labels {
		return host
	}
	return strings.Join(parts[len(parts)-labels:], ".")
}

// isSecondLevelSuffix reports whether a label belongs to a public suffix that is
// itself two labels long ("example.co.uk"), which needs one extra label to
// reach the registrable domain.
func isSecondLevelSuffix(label string) bool {
	switch label {
	case "co", "com", "net", "org", "gov", "edu", "ac", "or", "ne", "go", "in", "id", "io", "me", "sh":
		return true
	}
	return false
}
