package discovery

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// Generate creates subdomain candidates by prepending each word in the wordlist
// to the base domain. Blank lines and comments (#) are skipped.
// Returns deduplicated, fully-qualified subdomain strings.
func Generate(domain, wordlist string) ([]string, error) {
	f, err := os.Open(wordlist)
	if err != nil {
		return nil, fmt.Errorf("cannot open bruteforce wordlist: %w", err)
	}
	defer f.Close()

	domain = strings.ToLower(strings.TrimSpace(domain))
	seen := make(map[string]struct{})
	var subs []string

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		word := strings.TrimSpace(sc.Text())
		if word == "" || strings.HasPrefix(word, "#") {
			continue
		}
		sub := strings.ToLower(word) + "." + domain
		if _, ok := seen[sub]; ok {
			continue
		}
		seen[sub] = struct{}{}
		subs = append(subs, sub)
	}

	return subs, sc.Err()
}
