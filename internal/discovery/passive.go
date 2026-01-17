package discovery

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/0xStr1k3r/TakeoverX/internal/models"
)

const (
	defaultCrtSh       = "https://crt.sh"
	defaultCertSpotter = "https://api.certspotter.com/v1/issuances"
	maxBodyBytes       = 32 << 20
)

// Retry pacing for certificate transparency sources. Variables rather than
// constants so tests can exercise the retry path without waiting on real
// backoff delays.
var (
	ctRetryAttempts    = 3
	ctRetryBaseBackoff = 500 * time.Millisecond
)

// PassiveSource fetches candidate hostnames without sending traffic to the
// target, so enumeration leaves no trace in its logs.
//
// Certificate transparency logs are queried in order of reliability. crt.sh is
// by far the most complete but is frequently overloaded and answers 502 under
// load, so failures fall through to Cert Spotter rather than ending the run.
type PassiveSource struct {
	Client  *http.Client
	BaseURL string
	// FallbackURL overrides the second certificate transparency source. It is
	// a field rather than a constant so tests never reach the real internet.
	FallbackURL string
	MaxNames    int
}

type crtShEntry struct {
	CommonName string `json:"common_name"`
	NameValue  string `json:"name_value"`
}

type certSpotterEntry struct {
	DNSNames []string `json:"dns_names"`
}

// Discover returns every hostname ever issued under domain via certificate
// transparency. This is the fully automatic entry point: no wordlist, no DNS
// queries against the target, no prior recon required.
func (p *PassiveSource) Discover(ctx context.Context, domain string) ([]string, error) {
	domain = models.NormalizeDomain(domain)
	if err := validBase(domain); err != nil {
		return nil, err
	}

	var problems []string
	for _, source := range []struct {
		name  string
		fetch func(context.Context) ([]string, error)
	}{
		{"crt.sh", func(c context.Context) ([]string, error) { return p.fromCrtSh(c, domain) }},
		{"certspotter", func(c context.Context) ([]string, error) { return p.fromCertSpotter(c, domain) }},
	} {
		names, err := source.fetch(ctx)
		if err != nil {
			problems = append(problems, fmt.Sprintf("%s: %v", source.name, err))
			continue
		}
		if len(names) == 0 {
			// A working source that genuinely has no certificates is a valid
			// answer, not a reason to try the next one.
			return nil, nil
		}
		sort.Strings(names)
		if p.MaxNames > 0 && len(names) > p.MaxNames {
			names = names[:p.MaxNames]
		}
		return names, nil
	}

	return nil, fmt.Errorf("all certificate transparency sources failed (%s)", strings.Join(problems, "; "))
}

func (p *PassiveSource) fromCrtSh(ctx context.Context, domain string) ([]string, error) {
	base := p.BaseURL
	if base == "" {
		base = defaultCrtSh
	}
	url := fmt.Sprintf("%s/?q=%%25.%s&output=json", strings.TrimRight(base, "/"), domain)

	body, err := p.get(ctx, url, "TakeoverX/1.0 (+passive subdomain discovery)")
	if err != nil {
		return nil, err
	}
	if len(strings.TrimSpace(string(body))) == 0 {
		return nil, nil
	}

	var rows []crtShEntry
	if err := json.Unmarshal(body, &rows); err != nil {
		return nil, fmt.Errorf("parsing crt.sh response: %w", err)
	}

	var out []string
	for _, row := range rows {
		// name_value holds one or more newline-separated names and common_name
		// is a subset of it; splitting both handles wildcard certificates.
		for _, field := range []string{row.NameValue, row.CommonName} {
			out = appendNames(out, strings.Split(field, "\n"), domain)
		}
	}
	return out, nil
}

func (p *PassiveSource) fromCertSpotter(ctx context.Context, domain string) ([]string, error) {
	base := p.FallbackURL
	if base == "" {
		base = defaultCertSpotter
	}
	url := fmt.Sprintf("%s?domain=%s&include_subdomains=true&expand=dns_names",
		strings.TrimRight(base, "/"), domain)

	body, err := p.get(ctx, url, "TakeoverX/1.0 (+passive subdomain discovery)")
	if err != nil {
		return nil, err
	}

	var rows []certSpotterEntry
	if err := json.Unmarshal(body, &rows); err != nil {
		return nil, fmt.Errorf("parsing certspotter response: %w", err)
	}

	var out []string
	for _, row := range rows {
		out = appendNames(out, row.DNSNames, domain)
	}
	return out, nil
}

// get fetches a URL with retries. crt.sh in particular returns 502 and 429
// under load, both of which are worth another attempt.
func (p *PassiveSource) get(ctx context.Context, url, ua string) ([]byte, error) {
	client := p.Client
	if client == nil {
		client = &http.Client{Timeout: 60 * time.Second}
	}

	var lastErr error
	for attempt := 1; attempt <= ctRetryAttempts; attempt++ {
		if attempt > 1 {
			backoff := time.Duration(math.Pow(2, float64(attempt-2))) * ctRetryBaseBackoff
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(backoff):
			}
		}

		body, retryable, err := getOnce(ctx, client, url, ua)
		if err == nil {
			return body, nil
		}
		lastErr = err
		if !retryable {
			return nil, err
		}
	}
	return nil, fmt.Errorf("%w (after %d attempts)", lastErr, ctRetryAttempts)
}

func getOnce(ctx context.Context, client *http.Client, url, ua string) (body []byte, retryable bool, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, false, fmt.Errorf("building request: %w", err)
	}
	req.Header.Set("User-Agent", ua)
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		// Network blips are usually worth retrying.
		return nil, true, fmt.Errorf("request failed: %w", err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
		_ = resp.Body.Close()
	}()

	switch {
	case resp.StatusCode == http.StatusOK:
	case resp.StatusCode == http.StatusTooManyRequests, resp.StatusCode >= 500:
		return nil, true, fmt.Errorf("HTTP %d", resp.StatusCode)
	default:
		// 400 means the query itself is wrong; retrying cannot help.
		return nil, false, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	body, err = io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	if err != nil {
		return nil, true, fmt.Errorf("reading response: %w", err)
	}
	return body, false, nil
}

// appendNames normalises, filters and deduplicates candidate hostnames against
// the base domain.
func appendNames(dst []string, raw []string, domain string) []string {
	for _, name := range raw {
		name = strings.TrimSpace(strings.ToLower(name))
		if name == "" || strings.HasPrefix(name, "*.") {
			// A bare wildcard certificate proves the zone exists but names no
			// specific host, so it contributes nothing.
			continue
		}
		name = strings.TrimSuffix(name, ".")
		if name == domain || !strings.HasSuffix(name, "."+domain) {
			continue
		}
		if strings.ContainsAny(name, " \t\n") {
			continue
		}
		dup := false
		for _, existing := range dst {
			if existing == name {
				dup = true
				break
			}
		}
		if !dup {
			dst = append(dst, name)
		}
	}
	return dst
}
