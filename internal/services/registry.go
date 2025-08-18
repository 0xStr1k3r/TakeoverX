package services

import (
	"encoding/json"
	"fmt"
	"net"
	"sort"
	"strings"

	"github.com/0xStr1k3r/TakeoverX/internal/models"
)

// Registry holds every known takeover-prone provider, indexed for fast lookup.
type Registry struct {
	byCNAME map[string][]int // normalized pattern -> candidate fingerprint indices
	byIP    []ipEntry        // provider networks for A-record detection
	fps     []models.ServiceFingerprint
}

type ipEntry struct {
	net *net.IPNet
	idx int
}

// NewRegistry indexes fingerprints and validates them. An empty provider name
// or an unparsable CIDR is a data error: it is reported rather than silently
// ignored, because a silently dropped provider becomes a false negative.
//
// Duplicate patterns are tolerated. Several providers legitimately share a
// suffix (an S3 origin fronted by CloudFront, say), and refusing to load would
// take the whole tool down over a data quirk. Ties are broken deterministically
// by evidence strength, so results never depend on file order.
func NewRegistry(fps []models.ServiceFingerprint) (*Registry, error) {
	r := &Registry{byCNAME: make(map[string][]int), fps: fps}

	for i, fp := range fps {
		if strings.TrimSpace(fp.Name) == "" {
			return nil, fmt.Errorf("fingerprint %d: missing name", i)
		}
		if len(fp.CNAME) == 0 && len(fp.IPRanges) == 0 {
			return nil, fmt.Errorf("fingerprint %q: has neither cname nor ip_ranges", fp.Name)
		}
		for _, p := range fp.CNAME {
			p = normalizePattern(p)
			if p == "" {
				return nil, fmt.Errorf("fingerprint %q: empty cname pattern", fp.Name)
			}
			if !contains(r.byCNAME[p], i) {
				r.byCNAME[p] = append(r.byCNAME[p], i)
			}
		}
		for _, cidr := range fp.IPRanges {
			_, network, err := net.ParseCIDR(cidr)
			if err != nil {
				return nil, fmt.Errorf("fingerprint %q: bad cidr %q: %w", fp.Name, cidr, err)
			}
			r.byIP = append(r.byIP, ipEntry{net: network, idx: i})
		}
	}
	return r, nil
}

// Load parses an embedded or on-disk fingerprint database.
func Load(data []byte) (*Registry, error) {
	var fps []models.ServiceFingerprint
	if err := json.Unmarshal(data, &fps); err != nil {
		return nil, fmt.Errorf("parsing services.json: %w", err)
	}
	reg, err := NewRegistry(fps)
	if err != nil {
		return nil, err
	}
	return reg, nil
}

// Count returns the number of providers in the registry.
func (r *Registry) Count() int { return len(r.fps) }

// All returns the providers, sorted by name for stable reporting.
func (r *Registry) All() []models.ServiceFingerprint {
	out := append([]models.ServiceFingerprint(nil), r.fps...)
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Get returns the provider at idx.
func (r *Registry) Get(idx int) *models.ServiceFingerprint {
	if idx < 0 || idx >= len(r.fps) {
		return nil
	}
	return &r.fps[idx]
}

// Detect resolves the provider responsible for a CNAME chain.
//
// Matching is suffix-anchored, not substring: a CNAME of
// "s3.amazonaws.com.attacker.test" must not be credited to AWS S3. Every hop in
// the chain is considered so an indirect takeover (a -> b -> heroku) is still
// attributed correctly.
func (r *Registry) Detect(chain []string) (*models.ServiceFingerprint, string) {
	// Check the tail of the chain first: the last hop is the actual provider.
	for i := len(chain) - 1; i >= 0; i-- {
		hop := models.NormalizeDomain(chain[i])
		if hop == "" {
			continue
		}
		if idx := r.matchCNAME(hop); idx >= 0 {
			return r.Get(idx), hop
		}
	}
	return nil, ""
}

// matchCNAME returns the best fingerprint index for a host, or -1.
//
// Patterns come in two shapes and each is matched the way it is meant to be:
//
//   - A dotted pattern such as "s3.amazonaws.com" is suffix-anchored. A host
//     matches only when it equals the pattern or ends with ".pattern". Plain
//     substring matching would credit "s3.amazonaws.com.attacker.test" to AWS.
//   - A single-label pattern such as "s3-website" describes a DNS label
//     family ("s3-website-us-east-1"). It matches a host label that is equal
//     to it, or extends it with a hyphen — again, never mid-string.
//
// Within one pattern, the provider carrying the most fingerprint evidence
// wins, so an entry that can actually be proven takes precedence over a
// generic placeholder. Name breaks the remaining tie for stability.
func (r *Registry) matchCNAME(host string) int {
	best := -1
	bestPatternLen := -1

	for pattern, candidates := range r.byCNAME {
		if !patternMatches(host, pattern) {
			continue
		}
		// Prefer the most specific pattern that matched.
		if len(pattern) <= bestPatternLen {
			continue
		}
		bestPatternLen = len(pattern)
		best = r.pickBest(candidates)
	}
	return best
}

// patternMatches applies the matching rules described on matchCNAME.
func patternMatches(host, pattern string) bool {
	if host == "" || pattern == "" {
		return false
	}
	if strings.Contains(pattern, ".") {
		return host == pattern || strings.HasSuffix(host, "."+pattern)
	}
	for _, label := range strings.Split(host, ".") {
		if label == pattern || strings.HasPrefix(label, pattern+"-") {
			return true
		}
	}
	return false
}

// pickBest chooses the strongest fingerprint among equally specific candidates.
func (r *Registry) pickBest(candidates []int) int {
	if len(candidates) == 0 {
		return -1
	}
	best := candidates[0]
	for _, idx := range candidates[1:] {
		if stronger(r.fps[idx], r.fps[best]) {
			best = idx
		}
	}
	return best
}

// stronger reports whether a is a better fingerprint than b.
func stronger(a, b models.ServiceFingerprint) bool {
	scoreA := len(a.Fingerprints)
	if a.NXDomain {
		scoreA++
	}
	scoreB := len(b.Fingerprints)
	if b.NXDomain {
		scoreB++
	}
	if scoreA != scoreB {
		return scoreA > scoreB
	}
	return a.Name < b.Name
}

func contains(list []int, want int) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}

// DetectIP resolves a provider from resolved addresses, for services that use
// A records instead of CNAMEs (GitHub Pages, Cloudflare, AWS ELB).
func (r *Registry) DetectIP(ips []string) (*models.ServiceFingerprint, string) {
	for _, ip := range ips {
		parsed := net.ParseIP(ip)
		if parsed == nil {
			continue
		}
		for _, e := range r.byIP {
			if e.net.Contains(parsed) {
				return r.Get(e.idx), ip
			}
		}
	}
	return nil, ""
}

// normalizePattern lowercases a CNAME pattern and strips a leading dot, so
// ".s3-website" and "s3-website" behave identically under suffix matching.
func normalizePattern(p string) string {
	return strings.ToLower(strings.Trim(strings.TrimSpace(p), "."))
}
