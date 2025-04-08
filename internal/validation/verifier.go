package validation

import (
	"takeoverx/internal/httpclient"
	"takeoverx/internal/matcher"
	"takeoverx/internal/models"
)

const retryCount = 2

// Verify re-probes the domain retryCount times to confirm the fingerprint
// appears consistently. Returns true only if every retry confirms the match,
// eliminating transient responses and false positives.
func Verify(domain string, fp *models.ServiceFingerprint) bool {
	for i := 0; i < retryCount; i++ {
		result := httpclient.Probe(domain)
		if result.Error != nil {
			return false
		}
		bodyMatch := matcher.Match(fp, result.Body)
		headerMatch := matcher.MatchHeaders(fp, result.Headers)
		if !bodyMatch && !headerMatch {
			return false
		}
	}
	return true
}
