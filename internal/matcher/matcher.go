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

// MatchHeaders checks response headers for service-specific signatures.
// Headers are compared case-insensitively against the service name and any
// explicit header_fingerprints patterns defined in the fingerprint entry.
func MatchHeaders(fp *models.ServiceFingerprint, headers map[string]string) bool {
	serviceNameLower := strings.ToLower(fp.Name)

	probeHeaders := []string{"Server", "X-Powered-By", "Via", "X-Served-By", "X-Amz-Request-Id", "X-Github-Request-Id"}
	for _, hk := range probeHeaders {
		if val, ok := headers[hk]; ok {
			if strings.Contains(strings.ToLower(val), serviceNameLower) {
				return true
			}
		}
	}

	// Check explicit header fingerprint patterns from services.json
	for _, pattern := range fp.HeaderFingerprints {
		if pattern == "" {
			continue
		}
		lp := strings.ToLower(pattern)
		for _, v := range headers {
			if strings.Contains(strings.ToLower(v), lp) {
				return true
			}
		}
	}
	return false
}

