package loader

import (
	"bufio"
	"net"
	"os"
	"strings"
)

// LoadDomains reads a domain list from a file or a single domain string,
// deduplicates entries and returns only valid-looking hostnames.
func LoadDomains(wordlist string, single string) ([]string, error) {
	seen := make(map[string]struct{})
	var domains []string

	add := func(raw string) {
		raw = strings.TrimSpace(raw)
		raw = strings.ToLower(raw)
		// Strip http/https prefix if present
		raw = strings.TrimPrefix(raw, "https://")
		raw = strings.TrimPrefix(raw, "http://")
		raw = strings.TrimRight(raw, "/")
		if raw == "" {
			return
		}
		if _, ok := seen[raw]; ok {
			return
		}
		seen[raw] = struct{}{}
		domains = append(domains, raw)
	}

	if single != "" {
		add(single)
	}

	if wordlist != "" {
		f, err := os.Open(wordlist)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			add(sc.Text())
		}
		if err := sc.Err(); err != nil {
			return nil, err
		}
	}

	return filterValid(domains), nil
}

// filterValid removes entries that don't have at least one dot (i.e. bare labels).
func filterValid(domains []string) []string {
	var out []string
	for _, d := range domains {
		if strings.Contains(d, ".") {
			// Quick sanity check – host part must be parseable
			host, _, err := net.SplitHostPort(d)
			if err != nil {
				// no port – that's fine
				host = d
			}
			if host != "" {
				out = append(out, d)
			}
		}
	}
	return out
}
