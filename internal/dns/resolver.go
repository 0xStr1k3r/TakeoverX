package dns

import (
	"context"
	"net"
	"strings"
	"sync"
	"time"

	"takeoverx/internal/models"
)

const maxChainDepth = 10

var (
	resolver = net.DefaultResolver

	cache   = make(map[string]*models.DNSResult)
	cacheMu sync.RWMutex
)

// Resolve performs a full CNAME chain lookup for the given subdomain.
// Results are cached to avoid redundant lookups.
func Resolve(domain string) *models.DNSResult {
	cacheMu.RLock()
	if cached, ok := cache[domain]; ok {
		cacheMu.RUnlock()
		return cached
	}
	cacheMu.RUnlock()

	result := &models.DNSResult{Subdomain: domain}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	chain, nxdomain := resolveCNAMEChain(ctx, domain)
	result.NXDomain = nxdomain
	result.CNAMEChain = chain

	if len(chain) > 0 {
		result.CNAME = chain[0]
		// Check if the final hop in the chain is dead (NXDOMAIN)
		last := chain[len(chain)-1]
		addrs, aErr := resolver.LookupHost(ctx, last)
		if aErr != nil || len(addrs) == 0 {
			result.IsDead = true
		}
	}

	storeCache(domain, result)
	return result
}

// resolveCNAMEChain follows the CNAME chain starting from domain.
// Returns all CNAME targets found (excluding the original domain) and
// whether a NXDOMAIN was encountered during lookup.
func resolveCNAMEChain(ctx context.Context, domain string) (chain []string, nxdomain bool) {
	current := domain
	for depth := 0; depth < maxChainDepth; depth++ {
		hopCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		cname, err := resolver.LookupCNAME(hopCtx, current)
		cancel()

		if err != nil {
			errStr := err.Error()
			if isNXDomain(errStr) {
				nxdomain = true
			}
			break
		}

		// Strip trailing dot; LookupCNAME always appends one.
		cname = strings.TrimSuffix(cname, ".")
		normalCurrent := strings.TrimSuffix(current, ".")

		if cname == normalCurrent {
			// No more CNAME hops — this is a terminal A/AAAA record.
			break
		}

		chain = append(chain, cname)
		current = cname
	}
	return
}

// Exists performs a quick A-record check to determine if a subdomain resolves.
// Used by bruteforce mode to filter live subdomains.
func Exists(domain string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	addrs, err := resolver.LookupHost(ctx, domain)
	return err == nil && len(addrs) > 0
}

func storeCache(domain string, r *models.DNSResult) {
	cacheMu.Lock()
	cache[domain] = r
	cacheMu.Unlock()
}

func isNXDomain(errMsg string) bool {
	lower := strings.ToLower(errMsg)
	return strings.Contains(lower, "no such host") ||
		strings.Contains(lower, "nxdomain") ||
		strings.Contains(lower, "name does not resolve")
}

