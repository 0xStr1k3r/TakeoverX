package httpclient

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/0xStr1k3r/TakeoverX/internal/models"
)

// Client performs HTTP(S) probes with connection reuse, bounded reads, a
// token-bucket rate limit and an optional proxy.
type Client struct {
	http      *http.Client
	transport *http.Transport
	limiter   *rateLimiter
	timeout   time.Duration
	ua        string
	proxy     string
}

const maxBody = 1 << 20 // 1 MiB is plenty for a fingerprint page

// New builds a probe client. timeout bounds the whole request; proxy may be "".
func New(timeout time.Duration, rps int, proxy string) *Client {
	tr := &http.Transport{
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true}, // #nosec G402 -- fingerprinting dangling hostnames; certs are irrelevant and MITM interception is in scope.
		MaxIdleConns:        512,
		MaxIdleConnsPerHost: 64,
		MaxConnsPerHost:     64,
		IdleConnTimeout:     30 * time.Second,
		TLSHandshakeTimeout: 6 * time.Second,
		DisableCompression:  false,
		ForceAttemptHTTP2:   true,
	}
	if u, err := parseProxy(proxy); err == nil && proxy != "" {
		tr.Proxy = http.ProxyURL(u)
	}
	if timeout <= 0 {
		timeout = 12 * time.Second
	}
	c := &Client{
		transport: tr,
		timeout:   timeout,
		ua:        "TakeoverX/1.0 (+subdomain takeover scanner; authorized use only)",
		proxy:     proxy,
		limiter:   newRateLimiter(rps),
		http: &http.Client{
			Timeout:   timeout,
			Transport: tr,
			// Never follow redirects: the first response is the takeover evidence.
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
	return c
}

// parseProxy validates an outbound proxy URL. A malformed value is reported so
// the caller can warn instead of silently probing without the proxy.
func parseProxy(p string) (*url.URL, error) {
	u, err := url.Parse(p)
	if err != nil {
		return nil, err
	}
	if u.Scheme == "" || u.Host == "" {
		return nil, errBadProxy
	}
	return u, nil
}

var errBadProxy = errors.New("proxy must look like scheme://host:port")

// Probe fetches a hostname over HTTPS, falling back to HTTP. It returns the
// first successful response; failures populate Err instead of panicking.
func (c *Client) Probe(ctx context.Context, host string) *models.HTTPResult {
	res := &models.HTTPResult{Subdomain: host, Headers: map[string]string{}}
	host = models.NormalizeDomain(host)
	if host == "" {
		res.Err = "empty host"
		return res
	}

	var lastErr error
	for _, scheme := range []string{"https", "http"} {
		if err := c.limiter.Wait(ctx); err != nil {
			res.Err = err.Error()
			return res
		}
		url := scheme + "://" + host + "/"
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			lastErr = err
			continue
		}
		req.Header.Set("User-Agent", c.ua)
		req.Header.Set("Accept", "*/*")
		req.Close = false

		resp, err := c.http.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBody))
		_ = resp.Body.Close()

		res.URL = url
		res.StatusCode = resp.StatusCode
		res.Body = string(body)
		for k := range resp.Header {
			if v := resp.Header.Get(k); v != "" {
				res.Headers[k] = v
			}
		}
		res.Err = ""
		return res
	}

	if lastErr != nil {
		res.Err = cleanErr(lastErr)
	} else {
		res.Err = "no response"
	}
	return res
}

// cleanErr strips URL noise so reasons stay readable in reports.
func cleanErr(err error) string {
	msg := err.Error()
	if i := strings.Index(msg, ": "); i > 0 && strings.Contains(msg, "http") {
		return msg
	}
	msg = strings.ReplaceAll(msg, "https://", "")
	msg = strings.ReplaceAll(msg, "http://", "")
	if len(msg) > 120 {
		msg = msg[:120]
	}
	return msg
}

// SetProxy swaps the outbound proxy at runtime ("" clears it). It returns an
// error and leaves the current proxy untouched when the URL is invalid.
func (c *Client) SetProxy(proxy string) error {
	if proxy == "" {
		c.proxy = ""
		c.transport.Proxy = nil
		return nil
	}
	u, err := parseProxy(proxy)
	if err != nil {
		return err
	}
	c.proxy = proxy
	c.transport.Proxy = http.ProxyURL(u)
	return nil
}

// SetRate adjusts the request rate at runtime (0 disables limiting).
func (c *Client) SetRate(rps int) { c.limiter.SetRate(rps) }

// CloseIdle releases pooled connections.
func (c *Client) CloseIdle() {
	c.transport.CloseIdleConnections()
}

func (c *Client) String() string {
	return fmt.Sprintf("timeout=%s rate=%d proxy=%q", c.timeout, c.limiter.Rate(), c.proxy)
}
