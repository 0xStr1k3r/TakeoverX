package models

import "strings"

// RecordType is the DNS record kind that points a subdomain at a
// third-party resource. Takeover risk differs sharply per type.
type RecordType string

const (
	RecordNone  RecordType = "none"
	RecordCNAME RecordType = "CNAME"
	RecordA     RecordType = "A"
	RecordAAAA  RecordType = "AAAA"
	RecordNS    RecordType = "NS"
	RecordMX    RecordType = "MX"
	RecordTXT   RecordType = "TXT"
)

// Status is the triage outcome for one subdomain.
type Status string

const (
	StatusVulnerable Status = "VULNERABLE"
	StatusSafe       Status = "SAFE"
	StatusUnknown    Status = "UNKNOWN"
)

// Confidence grades how strong the evidence is. A CNAME pointing at a known
// provider is NOT a finding on its own — only a provider-specific
// "unclaimed" response (or a dead target) is.
type Confidence string

const (
	ConfidenceHigh   Confidence = "HIGH"   // definitive unclaimed response, or dead/NXDOMAIN target
	ConfidenceMedium Confidence = "MEDIUM" // generic provider error response
	ConfidenceLow    Confidence = "LOW"    // DNS points at provider, HTTP inconclusive
)

// ServiceFingerprint defines one takeover-prone provider.
type ServiceFingerprint struct {
	Name string `json:"name"`
	// CNAME suffixes that indicate this provider (matched against every hop).
	CNAME []string `json:"cname"`
	// Fingerprints are body substrings unique to the provider's unclaimed state.
	Fingerprints []string `json:"fingerprints"`
	// HeaderFingerprints are header-value substrings.
	HeaderFingerprints []string `json:"header_fingerprints,omitempty"`
	// IPRanges lists CIDRs the provider serves from (for A-record detection).
	IPRanges []string `json:"ip_ranges,omitempty"`
	// NXDomain marks providers whose takeover is proven by a dead target.
	NXDomain bool `json:"nxdomain"`
	// Claimable is false for providers that cannot be claimed (informational).
	Claimable bool `json:"claimable"`
	// DocsURL points at the provider's claim instructions.
	DocsURL string `json:"docs,omitempty"`
	// Severity is the business impact when claimed.
	Severity string `json:"severity,omitempty"`
}

// DNSResult holds everything learned from DNS resolution of a subdomain.
type DNSResult struct {
	Subdomain  string
	RecordType RecordType
	CNAME      string
	CNAMEChain []string
	IPs        []string
	NS         []string
	MX         []string
	TXT        []string
	NXDomain   bool
	IsDead     bool
	Wildcard   bool   // matched by a wildcard DNS record on the parent
	Err        string // resolver error text, if any
}

// HTTPResult holds the outcome of one HTTP probe.
type HTTPResult struct {
	Subdomain  string
	URL        string
	StatusCode int
	Body       string
	Headers    map[string]string
	Err        string
}

// ScanResult is the final, reportable outcome for one subdomain.
type ScanResult struct {
	Subdomain   string   `json:"subdomain"`
	RecordType  string   `json:"record_type,omitempty"`
	CNAME       string   `json:"cname,omitempty"`
	CNAMEChain  string   `json:"cname_chain,omitempty"`
	IPs         []string `json:"ips,omitempty"`
	Service     string   `json:"service"`
	Status      string   `json:"status"`
	Confidence  string   `json:"confidence,omitempty"`
	Reason      string   `json:"reason,omitempty"`
	Remediation string   `json:"remediation,omitempty"`
	DocsURL     string   `json:"docs,omitempty"`
	Severity    string   `json:"severity,omitempty"`
	MatchedBy   string   `json:"matched_by,omitempty"`
	Steps       []string `json:"steps,omitempty"`
	Duration    float64  `json:"duration_ms,omitempty"`
}

// Vulnerable reports whether the result is an actionable finding.
func (r ScanResult) Vulnerable() bool { return r.Status == string(StatusVulnerable) }

// ServiceFingerprint.HasClaimPath reports whether this provider is actually
// claimable. Non-claimable providers are reported as UNKNOWN, never VULNERABLE.
func (f ServiceFingerprint) HasClaimPath() bool { return f.Claimable }

// Normalize lowercases and trims a hostname for comparison.
func NormalizeDomain(d string) string {
	return strings.ToLower(strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(d), ".")))
}
