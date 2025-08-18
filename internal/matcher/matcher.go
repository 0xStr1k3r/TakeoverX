package matcher

import (
	"strings"

	"github.com/0xStr1k3r/TakeoverX/internal/models"
)

// Evidence records exactly what matched, so a finding can explain itself and
// two providers can be told apart when several could plausibly match.
type Evidence struct {
	Kind  string `json:"kind"` // "body" | "header" | "cname" | "ip" | "dead"
	Value string `json:"value,omitempty"`
}

// Match reports whether a response body contains any provider fingerprint.
// Empty patterns are skipped: a provider with a blank entry must never match
// everything.
func Match(fp *models.ServiceFingerprint, body string) (bool, string) {
	if body == "" {
		return false, ""
	}
	for _, f := range fp.Fingerprints {
		if f == "" {
			continue
		}
		if strings.Contains(body, f) {
			return true, f
		}
	}
	return false, ""
}

// MatchHeaders reports whether response headers carry a provider signature.
// Header names are compared case-insensitively (canonicalised), and so are the
// values, so "Server: amazons3" still matches a lower-case pattern.
func MatchHeaders(fp *models.ServiceFingerprint, headers map[string]string) (bool, string) {
	if len(headers) == 0 {
		return false, ""
	}

	// Providers routinely advertise themselves in these headers.
	for name := range headers {
		lowerName := strings.ToLower(name)
		if !isIdentifyingHeader(lowerName) {
			continue
		}
		value := strings.ToLower(headers[name])
		if value == "" {
			continue
		}
		for _, want := range fp.HeaderFingerprints {
			if want != "" && strings.Contains(value, strings.ToLower(want)) {
				return true, headers[name]
			}
		}
		if strings.Contains(value, strings.ToLower(fp.Name)) {
			return true, headers[name]
		}
	}
	return false, ""
}

// isIdentifyingHeader limits header matching to headers that actually identify
// the serving platform. Matching the service name against, say, Content-Type or
// Cache-Control produces nonsense matches.
func isIdentifyingHeader(lower string) bool {
	switch lower {
	case "server", "x-powered-by", "via", "x-served-by", "x-amz-request-id",
		"x-amz-id-2", "x-amz-cf-id", "x-github-request-id", "x-vercel-id",
		"x-nf-request-id", "x-netlify-request-id", "x-shopify-stage",
		"x-render-origin-server", "cf-ray", "fly-request-id":
		return true
	}
	return false
}
