package services

import (
	"encoding/json"
	"strings"

	"takeoverx/internal/models"
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

	for i, fp := range fingerprints {
		for _, candidate := range candidates {
			lower := strings.ToLower(candidate)
			for _, pattern := range fp.CNAME {
				if pattern == "" {
					continue
				}
				if strings.Contains(lower, strings.ToLower(pattern)) {
					return &fingerprints[i]
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
