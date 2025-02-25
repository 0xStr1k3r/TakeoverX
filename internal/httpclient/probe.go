package httpclient

import (
	"crypto/tls"
	"io"
	"net/http"
	"sync"
	"time"

	"takeoverx/internal/models"
)

var sharedTransport = &http.Transport{
	TLSClientConfig:       &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
	MaxIdleConns:          500,
	MaxIdleConnsPerHost:   100,
	IdleConnTimeout:       30 * time.Second,
	ResponseHeaderTimeout: 10 * time.Second,
	DisableKeepAlives:     false,
}

var client = &http.Client{
	Timeout:   12 * time.Second,
	Transport: sharedTransport,
	// Do not follow redirects so we capture the real takeover response.
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

// ── Rate limiter ──────────────────────────────────────────────────────────────

var (
	tokenCh   chan struct{}
	tokenOnce sync.Once
)

// SetRateLimit configures a token-bucket rate limiter at rps requests/second.
// Call once before scanning begins; zero or negative disables rate limiting.
func SetRateLimit(rps int) {
	if rps <= 0 {
		return
	}
	tokenOnce.Do(func() {
		tokenCh = make(chan struct{}, rps)
		interval := time.Second / time.Duration(rps)
		go func() {
			ticker := time.NewTicker(interval)
			defer ticker.Stop()
			for range ticker.C {
				select {
				case tokenCh <- struct{}{}:
				default:
				}
			}
		}()
	})
}

func acquireToken() {
	if tokenCh == nil {
		return
	}
	<-tokenCh
}

// ── SetTimeout ────────────────────────────────────────────────────────────────

// SetTimeout updates the shared HTTP client timeout. Call before scanning starts.
func SetTimeout(d time.Duration) {
	client.Timeout = d
	sharedTransport.ResponseHeaderTimeout = d
}

// ── Probe ─────────────────────────────────────────────────────────────────────

// Probe sends an HTTP GET to the subdomain and returns an HTTPResult.
// It tries HTTPS first, falling back to HTTP on error.
func Probe(domain string) *models.HTTPResult {
	acquireToken()

	result := &models.HTTPResult{Subdomain: domain}

	for _, scheme := range []string{"https", "http"} {
		url := scheme + "://" + domain
		resp, err := client.Get(url)
		if err != nil {
			result.Error = err
			continue
		}

		// Read up to 1 MB — close immediately, do NOT defer inside a loop.
		limited := io.LimitReader(resp.Body, 1<<20)
		body, _ := io.ReadAll(limited)
		resp.Body.Close()

		result.StatusCode = resp.StatusCode
		result.Body = string(body)
		result.Headers = make(map[string]string)
		for k, v := range resp.Header {
			if len(v) > 0 {
				result.Headers[k] = v[0]
			}
		}
		result.Error = nil
		return result
	}

	return result
}

