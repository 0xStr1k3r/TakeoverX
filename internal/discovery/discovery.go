package discovery

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/0xStr1k3r/TakeoverX/internal/models"
)

// ── wordlist bruteforce ──────────────────────────────────────────────────────

// Generate creates subdomain candidates by qualifying each prefix word with the
// base domain. Blank lines and comments are skipped and results deduplicated.
func Generate(domain, wordlist string) ([]string, error) {
	f, err := os.Open(wordlist)
	if err != nil {
		return nil, fmt.Errorf("cannot open bruteforce wordlist: %w", err)
	}
	defer f.Close()

	domain = models.NormalizeDomain(domain)
	if err := validBase(domain); err != nil {
		return nil, err
	}

	seen := make(map[string]struct{})
	var subs []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		word := strings.TrimSpace(sc.Text())
		if i := strings.IndexAny(word, "#;"); i >= 0 {
			word = strings.TrimSpace(word[:i])
		}
		if word == "" {
			continue
		}
		sub := models.NormalizeDomain(word + "." + domain)
		if _, ok := seen[sub]; ok {
			continue
		}
		seen[sub] = struct{}{}
		subs = append(subs, sub)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("reading %q: %w", wordlist, err)
	}
	if len(subs) == 0 {
		return nil, fmt.Errorf("wordlist %q contained no usable prefixes", wordlist)
	}
	return subs, nil
}

func validBase(domain string) error {
	if domain == "" {
		return fmt.Errorf("a base domain is required for bruteforce mode (-d)")
	}
	if !strings.Contains(domain, ".") {
		return fmt.Errorf("base domain %q is not fully qualified", domain)
	}
	return nil
}

// ── parallelism ──────────────────────────────────────────────────────────────

// Stream yields subdomain candidates from a slice using a bounded worker pool,
// so a 500k-word bruteforce does not allocate 500k concurrent goroutines.
func Stream(ctx context.Context, items []string, workers int, fn func(context.Context, string) error) error {
	if workers < 1 {
		workers = 10
	}
	if len(items) == 0 {
		return nil
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	jobs := make(chan string, workers*2)
	var wg sync.WaitGroup
	var mu sync.Mutex
	var firstErr error

	record := func(err error) {
		if err == nil {
			return
		}
		mu.Lock()
		if firstErr == nil {
			firstErr = err
			cancel()
		}
		mu.Unlock()
	}

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for item := range jobs {
				if ctx.Err() != nil {
					return
				}
				record(fn(ctx, item))
			}
		}()
	}

feed:
	for _, it := range items {
		select {
		case jobs <- it:
		case <-ctx.Done():
			break feed
		}
	}
	close(jobs)
	wg.Wait()

	return firstErr
}

// BuiltinPrefixes is a small, high-yield list used when no wordlist is given,
// so bruteforce mode works out of the box.
var BuiltinPrefixes = []string{
	"www", "mail", "ftp", "dev", "staging", "stage", "test", "qa", "uat", "prod",
	"api", "api2", "api-v2", "rest", "graphql", "gateway", "admin", "portal",
	"app", "apps", "mobile", "dashboard", "console", "panel", "internal",
	"blog", "shop", "store", "cdn", "static", "assets", "media", "img", "files",
	"docs", "help", "support", "status", "wiki", "git", "gitlab", "jenkins",
	"ci", "build", "deploy", "vpn", "remote", "ssh", "mx", "smtp", "imap", "ns",
	"ns1", "ns2", "db", "sql", "mysql", "redis", "kafka", "metrics", "grafana",
	"kibana", "logs", "elk", "auth", "login", "sso", "oauth", "id", "identity",
	"payments", "pay", "billing", "checkout", "webhook", "hooks", "events",
	"analytics", "track", "ads", "marketing", "email", "newsletter", "chat",
	"forum", "wiki2", "lab", "demo", "beta", "alpha", "preview", "sandbox",
	"legacy", "old", "new", "v1", "v2", "eu", "us", "asia", "cloud", "edge",
	"origin", "backend", "frontend", "proxy", "lb", "elb", "k8s", "docker",
}

// DefaultWordlist writes the built-in prefixes to path, so users can extend a
// real file instead of having to start from nothing.
func DefaultWordlist(path string) error {
	var b strings.Builder
	b.WriteString("# TakeoverX default subdomain prefixes\n")
	for _, w := range BuiltinPrefixes {
		b.WriteString(w + "\n")
	}
	if err := os.WriteFile(path, []byte(b.String()), 0o600); err != nil {
		return fmt.Errorf("writing default wordlist: %w", err)
	}
	return nil
}
