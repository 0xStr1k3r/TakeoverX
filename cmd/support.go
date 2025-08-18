package cmd

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/0xStr1k3r/TakeoverX/internal/validation"
)

// ── progress ─────────────────────────────────────────────────────────────────

// progress renders a single updating line on stderr. Findings are printed
// immediately as they are confirmed, because a long scan that is interrupted
// must still leave the operator with whatever was already established.
type progress struct {
	total int
	seen  int
	found int
	w     io.Writer
	mu    sync.Mutex
	tty   bool
	last  time.Time
}

func newProgress(total int) *progress {
	return &progress{total: total, w: io.Discard, tty: isTTY()}
}

func (p *progress) tick(r validation.Result) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.seen++

	if r.Status == "VULNERABLE" {
		p.found++
		if p.tty {
			fmt.Fprint(p.w, "\r\033[K")
		}
		fmt.Fprintf(p.w, "[!] %s  %s (%s confidence)\n      %s\n",
			r.Subdomain, providerName(r), r.Confidence, r.Reason)
	}
	p.render()
}

func (p *progress) render() {
	if opts.quiet || p.total == 0 {
		return
	}
	if !p.tty {
		// Non-interactive output stays one line per checkpoint instead of
		// emitting thousands of carriage-return updates into a log file.
		if p.seen%100 != 0 && p.seen != p.total {
			return
		}
		fmt.Fprintf(p.w, "[*] %d/%d checked, %d finding(s)\n", p.seen, p.total, p.found)
		return
	}
	fmt.Fprintf(p.w, "\r\033[K[*] %d/%d  findings: %d", p.seen, p.total, p.found)
}

func (p *progress) finish() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if opts.quiet || !p.tty {
		return
	}
	fmt.Fprint(p.w, "\r\033[K")
}

func providerName(r validation.Result) string {
	if r.Service == nil {
		return "unknown service"
	}
	return r.Service.Name
}

// ── wildcard cache ───────────────────────────────────────────────────────────

// wildcardCache memoises wildcard-DNS probes per registrable domain. Each probe
// costs two DNS queries, and a large scan touches the same zone thousands of
// times.
type wildcardCache struct {
	check func(string) bool
	mu    sync.Mutex
	seen  map[string]bool
	// inflight holds one channel per zone being probed, so that a hundred
	// workers arriving at the same uncached zone wait for one probe rather
	// than each starting their own.
	inflight map[string]*probe
}

type probe struct {
	done   chan struct{}
	active bool
}

func newWildcardCache(check func(string) bool) *wildcardCache {
	return &wildcardCache{
		check:    check,
		seen:     map[string]bool{},
		inflight: map[string]*probe{},
	}
}

// isWildcard reports whether the zone publishes wildcard DNS. A blank base is
// never probed.
func (c *wildcardCache) isWildcard(base string) bool {
	if base == "" || !strings.Contains(base, ".") {
		return false
	}
	for {
		c.mu.Lock()
		if active, ok := c.seen[base]; ok {
			c.mu.Unlock()
			return active
		}
		if p, ok := c.inflight[base]; ok {
			// Another worker is already probing this zone; wait for it rather
			// than duplicating the query.
			c.mu.Unlock()
			<-p.done
			continue
		}
		p := &probe{done: make(chan struct{})}
		c.inflight[base] = p
		c.mu.Unlock()

		active := c.check(base)

		c.mu.Lock()
		p.active = active
		c.seen[base] = active
		delete(c.inflight, base)
		c.mu.Unlock()
		close(p.done)
		return active
	}
}

// ── misc ─────────────────────────────────────────────────────────────────────

func parseProxyFlag(p string) (*url.URL, error) {
	u, err := url.Parse(p)
	if err != nil {
		return nil, err
	}
	if u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("must look like scheme://host:port, got %q", p)
	}
	return u, nil
}

// httpClientNoTimeout is used for passive discovery, which has its own longer
// deadline and must not inherit the per-probe HTTP timeout.
func httpClientNoTimeout() *http.Client {
	return &http.Client{Timeout: 60 * time.Second}
}
