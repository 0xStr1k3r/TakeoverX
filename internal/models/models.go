package models

// ServiceFingerprint defines a cloud service with CNAME patterns and HTTP fingerprints.
type ServiceFingerprint struct {
	Name               string   `json:"name"`
	CNAME              []string `json:"cname"`
	Fingerprints       []string `json:"fingerprints"`
	HeaderFingerprints []string `json:"header_fingerprints,omitempty"`
	NXDomain           bool     `json:"nxdomain"`
}

// DNSResult holds the result of a DNS lookup for a subdomain.
type DNSResult struct {
	Subdomain  string
	CNAME      string   // primary (first) CNAME
	CNAMEChain []string // full resolved CNAME chain
	NXDomain   bool
	IsDead     bool // CNAME chain resolves but ultimate target is NXDOMAIN
}

// HTTPResult holds the result of an HTTP probe.
type HTTPResult struct {
	Subdomain  string
	StatusCode int
	Body       string
	Headers    map[string]string
	Error      error
}

// ScanResult is the final aggregated result for a subdomain.
type ScanResult struct {
	Subdomain  string `json:"subdomain"`
	CNAME      string `json:"cname,omitempty"`
	CNAMEChain string `json:"cname_chain,omitempty"`
	Service    string `json:"service"`
	Status     string `json:"status"` // VULNERABLE, SAFE, UNKNOWN
	Reason     string `json:"reason,omitempty"`
}

