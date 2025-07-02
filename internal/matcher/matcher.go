package matcher

import (
	"strings"

	"github.com/0xStr1k3r/TakeoverX/internal/models"
)

// Match checks whether an HTTP response body contains any of the service fingerprints.
func Match(fp *models.ServiceFingerprint, body string) bool {
	for _, fingerprint := range fp.Fingerprints {
		if fingerprint == "" {
			continue
		}
		if strings.Contains(body, fingerprint) {
			return true
		}
	}
	return false
}

// identifyingHeaders are the response headers that name the platform serving
// the request. Matching anywhere else produces nonsense: a Cache-Control of
// "cloudflare" is not evidence that Cloudflare serves the site.
var identifyingHeaders = map[string]bool{
	"server": true, "x-powered-by": true, "via": true, "x-served-by": true,
	"x-amz-request-id": true, "x-amz-id-2": true, "x-amz-cf-id": true,
	"x-github-request-id": true, "x-vercel-id": true, "x-nf-request-id": true,
	"x-netlify-request-id": true, "x-shopify-stage": true,
	"x-render-origin-server": true, "cf-ray": true, "fly-request-id": true,
}

// MatchHeaders checks response headers for service-specific signatures.
// Header names and values are both compared case-insensitively.
func MatchHeaders(fp *models.ServiceFingerprint, headers map[string]string) bool {
	if len(headers) == 0 {
		return false
	}
	serviceNameLower := strings.ToLower(fp.Name)

	for name, value := range headers {
		if !identifyingHeaders[strings.ToLower(name)] {
			continue
		}
		lower := strings.ToLower(value)
		if lower == "" {
			continue
		}
		if strings.Contains(lower, serviceNameLower) {
			return true
		}
		// Check explicit header fingerprint patterns from services.json
		for _, pattern := range fp.HeaderFingerprints {
			if pattern != "" && strings.Contains(lower, strings.ToLower(pattern)) {
				return true
			}
		}
	}
	return false
}

