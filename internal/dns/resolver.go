package dns

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/0xStr1k3r/TakeoverX/internal/models"
)

const (
	maxChainDepth = 12
	lookupTimeout = 5 * time.Second
	resolveBudget = 10 * time.Second
)

var resolver Resolver = net.DefaultResolver

type cacheEntry struct {
	result *models.DNSResult
	at     time.Time
}

var (
	cache   = make(map[string]cacheEntry)
	cacheMu sync.RWMutex
)

// Resolver is the subset of net.Resolver used here — tests substitute fakes.
type Resolver interface {
	LookupCNAME(ctx context.Context, host string) (string, error)
	LookupHost(ctx context.Context, host string) ([]string, error)
}

// SetResolver swaps the DNS backend (used by tests).
func SetResolver(r Resolver) {
	if r != nil {
		resolver = r
	}
}

// Resolve collects every DNS fact we need about a subdomain: which record
// type points it somewhere, the full CNAME chain, addresses, and whether the
// chain terminates in a dead (NXDOMAIN) target.
func Resolve(domain string) *models.DNSResult {
	domain = models.NormalizeDomain(domain)
	domain = strings.TrimSuffix(domain, ".")

	cacheMu.RLock()
	if e, ok := cache[domain]; ok {
		cacheMu.RUnlock()
		return e.result
	}
	cacheMu.RUnlock()

	ctx, cancel := context.WithTimeout(context.Background(), resolveBudget)
	defer cancel()

	res := &models.DNSResult{Subdomain: domain}

	// resolveChain returns the addresses it already looked up, so the common
	// case costs one query per name rather than three.
	res.RecordType, res.CNAMEChain, res.IPs = resolveChain(ctx, domain)
	res.NXDomain = res.RecordType == models.RecordNone && len(res.IPs) == 0

	if len(res.CNAMEChain) > 0 {
		res.CNAME = res.CNAMEChain[0]

		// Dead target: the CNAME chain resolves but the final hop has no
		// address. This is the evidence for providers whose takeover manifests
		// as a vanished resource.
		last := res.CNAMEChain[len(res.CNAMEChain)-1]
		lctx, lcancel := context.WithTimeout(ctx, lookupTimeout)
		addrs, err := resolver.LookupHost(lctx, last)
		lcancel()
		if err != nil || len(addrs) == 0 {
			res.IsDead = true
		}
	}

	storeCache(domain, res)
	return res
}

// resolveChain returns the record type, the CNAME chain, and any addresses
// already resolved for the queried name (avoiding a duplicate A lookup).
func resolveChain(ctx context.Context, domain string) (models.RecordType, []string, []string) {
	addrs, hostErr := resolver.LookupHost(ctx, domain)
	addrs = dedupe(addrs)

	// A bruteforce run is dominated by names that do not exist. NXDOMAIN from
	// the address query settles it: the name is absent from the zone, so the
	// CNAME query can only fail as well. Skipping it halves the queries for
	// every miss, which is the overwhelming majority of a generated list.
	if isNotFound(hostErr) && len(addrs) == 0 {
		return models.RecordNone, nil, nil
	}

	cctx, cancel := context.WithTimeout(ctx, lookupTimeout)
	cname, err := resolver.LookupCNAME(cctx, domain)
	cancel()
	normal := strings.TrimSuffix(domain, ".")

	if err == nil {
		cname = strings.TrimSuffix(cname, ".")
		if cname != "" && cname != normal {
			chain := []string{cname}
			current := cname
			for i := 0; i < maxChainDepth; i++ {
				hctx, hcancel := context.WithTimeout(ctx, lookupTimeout)
				next, nerr := resolver.LookupCNAME(hctx, current)
				hcancel()
				if nerr != nil {
					break
				}
				next = strings.TrimSuffix(next, ".")
				if next == "" || next == current {
					break
				}
				chain = append(chain, next)
				current = next
			}
			return models.RecordCNAME, chain, addrs
		}
	}

	if len(addrs) > 0 {
		for _, a := range addrs {
			if strings.Contains(a, ":") {
				return models.RecordAAAA, nil, addrs
			}
		}
		return models.RecordA, nil, addrs
	}
	return models.RecordNone, nil, nil
}

// WildcardActive reports whether the parent domain answers for an arbitrary,
// randomly generated subdomain. When it does, every "resolved" name in this
// zone is suspect and CNAME matches alone prove nothing.
func WildcardActive(base string) bool {
	base = models.NormalizeDomain(base)
	if base == "" || !strings.Contains(base, ".") {
		return false
	}
	probe := fmt.Sprintf("takeoverx-wildcard-probe-%x.example", time.Now().UnixNano())
	cctx, cancel := context.WithTimeout(context.Background(), resolveBudget)
	defer cancel()
	addrs, err := resolver.LookupHost(cctx, probe+"."+base)
	if err == nil && len(addrs) > 0 {
		return true
	}
	cname, err := resolver.LookupCNAME(cctx, probe+"."+base)
	return err == nil && cname != "" && cname != probe+"."+base
}

func dedupe(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, v := range in {
		if v != "" && !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}

// ResetCache clears memoized lookups (tests, long-lived processes).
func ResetCache() {
	cacheMu.Lock()
	cache = make(map[string]cacheEntry)
	cacheMu.Unlock()
}

func storeCache(domain string, r *models.DNSResult) {
	cacheMu.Lock()
	cache[domain] = cacheEntry{result: r, at: time.Now()}
	cacheMu.Unlock()
}

// CachedCount reports how many lookups are memoized (shown with --stats).
func CachedCount() int {
	cacheMu.RLock()
	defer cacheMu.RUnlock()
	return len(cache)
}

// DefaultResolverForTest returns the resolver currently installed, so a test
// outside this package can restore it after substituting a fake.
func DefaultResolverForTest() Resolver { return resolver }

// isNotFound reports whether a resolver error means the name definitively does
// not exist, as opposed to a timeout or a transient server failure.
func isNotFound(err error) bool {
	if err == nil {
		return false
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return dnsErr.IsNotFound
	}
	return false
}
