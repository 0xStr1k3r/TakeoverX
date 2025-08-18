package discovery

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/0xStr1k3r/TakeoverX/internal/models"
)

const (
	defaultCrtSh = "https://crt.sh"
	maxBodyBytes = 32 << 20
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
	MaxNames    int
}

type crtShEntry struct {
	CommonName string `json:"common_name"`
	NameValue  string `json:"name_value"`
}

// Discover returns every hostname ever issued under domain via certificate
// transparency. This is the fully automatic entry point: no wordlist, no DNS
// queries against the target, no prior recon required.
func (p *PassiveSource) Discover(ctx context.Context, domain string) ([]string, error) {
	domain = models.NormalizeDomain(domain)
	if err := validBase(domain); err != nil {
		return nil, err
	}

	names, err := p.fromCrtSh(ctx, domain)
	if err != nil {
		return nil, err
	}
	sort.Strings(names)
	if p.MaxNames > 0 && len(names) > p.MaxNames {
		names = names[:p.MaxNames]
	}
	return names, nil
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

// get performs the request. A non-200 is reported rather than retried.
func (p *PassiveSource) get(ctx context.Context, url, ua string) ([]byte, error) {
	client := p.Client
	if client == nil {
		client = &http.Client{Timeout: 60 * time.Second}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("building request: %w", err)
	}
	req.Header.Set("User-Agent", ua)
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
		_ = resp.Body.Close()
	}()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("certificate transparency query returned HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}
	return body, nil
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
