package services

import (
	"encoding/json"
	"strings"

	"github.com/0xStr1k3r/TakeoverX/internal/models"
)

// Detect returns the first matching ServiceFingerprint by checking the
// primary CNAME and every hop in the full CNAME chain against service patterns.
// Returns nil if no service matches.
func Detect(primary string, chain []string, fingerprints []models.ServiceFingerprint) *models.ServiceFingerprint {
	candidates := make([]string, 0, len(chain)+1)
	if primary != "" {
		candidates = append(candidates, primary)
	}
	for _, hop := range chain {
		if hop != "" {
			candidates = append(candidates, hop)
		}
	}

	// The last hop is the service actually serving the name. An earlier hop can
	// point anywhere, so attributing a chain to its first CNAME names the wrong
	// provider often enough to matter.
	for i := len(candidates) - 1; i >= 0; i-- {
		fp := fingerprints[i]
		for _, candidate := range candidates {
			lower := strings.ToLower(candidate)
			for _, pattern := range fp.CNAME {
				if pattern == "" {
					continue
				}
				if strings.Contains(lower, strings.ToLower(pattern)) {
					return &fp
				}
			}
		}
	}
	return nil
}

// LoadFingerprints parses the embedded services.json bytes into a slice of ServiceFingerprint.
func LoadFingerprints(data []byte) ([]models.ServiceFingerprint, error) {
	var fps []models.ServiceFingerprint
	if err := json.Unmarshal(data, &fps); err != nil {
		return nil, err
	}
	return fps, nil
}
