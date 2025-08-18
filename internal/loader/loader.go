package loader

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/0xStr1k3r/TakeoverX/internal/models"
)

// Source describes where a hostname list came from, for reporting.
type Source struct {
	Kind  string // "flag", "file", "stdin"
	Value string
}

// Result is the outcome of loading a target list.
type Result struct {
	Domains   []string
	Rejected  []Rejection
	Sources   []Source
	Duplicate int
	Expanded  int
}

// Rejection records an input line that could not be used, and why.
type Rejection struct {
	Input  string `json:"input"`
	Reason string `json:"reason"`
}

// Options controls how input is normalised.
type Options struct {
	// Base, when set, qualifies bare labels (e.g. "api" + "example.com").
	Base string
	// AllowWildcardLines expands "*.example.com" to "example.com".
	AllowWildcardLines bool
}

// Load reads hostnames from a single value, a file and/or stdin, normalises
// them, drops duplicates and rejects anything that is not a usable hostname.
//
// Rejections are returned rather than silently dropped so the operator can see
// exactly which inputs were ignored and why.
func Load(single, path string, stdin io.Reader, opts Options) (*Result, error) {
	res := &Result{}
	seen := make(map[string]struct{})
	base := models.NormalizeDomain(opts.Base)

	add := func(raw, origin, label string) {
		host, rej := normalizeInput(raw, base, opts.AllowWildcardLines)
		if rej != "" {
			res.Rejected = append(res.Rejected, Rejection{Input: strings.TrimSpace(raw), Reason: rej})
			return
		}
		if _, dup := seen[host]; dup {
			res.Duplicate++
			return
		}
		seen[host] = struct{}{}
		res.Domains = append(res.Domains, host)
		res.Sources = append(res.Sources, Source{Kind: origin, Value: label})
	}

	if single != "" {
		add(single, "flag", single)
	}

	if path != "" {
		f, err := os.Open(path)
		if err != nil {
			return nil, fmt.Errorf("cannot read wordlist %q: %w", path, err)
		}
		defer f.Close()
		n, err := consume(f, add)
		if err != nil {
			return nil, fmt.Errorf("reading %q: %w", path, err)
		}
		res.Expanded += n
		res.Sources = append(res.Sources, Source{Kind: "file", Value: path})
		if len(res.Domains) == 0 {
			return nil, fmt.Errorf("wordlist %q contained no usable hostnames (%d rejected)", path, len(res.Rejected))
		}
	}

	if stdin != nil {
		n, err := consume(stdin, add)
		if err != nil {
			return nil, fmt.Errorf("reading stdin: %w", err)
		}
		res.Expanded += n
		res.Sources = append(res.Sources, Source{Kind: "stdin", Value: "-"})
	}

	if len(res.Domains) == 0 {
		return nil, fmt.Errorf("no valid hostnames supplied: pass -d, -w or pipe a list on stdin")
	}
	return res, nil
}

func consume(r io.Reader, add func(string, string, string)) (int, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	added := 0
	for sc.Scan() {
		add(sc.Text(), "stdin", "-")
		added++
	}
	return added, sc.Err()
}

// normalizeInput turns a raw input line into a lowercase, fully-qualified,
// port-free hostname, or explains why it cannot be used.
func normalizeInput(raw, base string, allowWildcard bool) (string, string) {
	v := strings.TrimSpace(raw)
	if v == "" {
		return "", "empty line"
	}
	if i := strings.IndexAny(v, "#;"); i >= 0 {
		v = strings.TrimSpace(v[:i])
	}
	if v == "" {
		return "", "comment only"
	}
	for _, scheme := range []string{"https://", "http://"} {
		if len(v) >= len(scheme) && strings.EqualFold(v[:len(scheme)], scheme) {
			v = v[len(scheme):]
			break
		}
	}
	v = strings.TrimRight(v, "/")
	if v == "" {
		return "", "no host after scheme"
	}

	// Reject anything with a path, credentials, query or fragment — those are
	// URLs, not hostnames, and passing them to the resolver yields nonsense.
	if strings.ContainsAny(v, "/?#@ \t") {
		return "", "not a bare hostname (contains path, query, credentials or space)"
	}

	// Strip a port if present. A host:port target is meaningless for DNS
	// takeover analysis, but silently keeping the port breaks every lookup.
	if strings.HasPrefix(v, "[") { // bracketed IPv6
		if end := strings.Index(v, "]"); end > 0 {
			host := v[1:end]
			if strings.Contains(host, ":") {
				return "", "IPv6 literal is not a subdomain target"
			}
			return models.NormalizeDomain(host), ""
		}
		return "", "malformed IPv6 literal"
	}
	if i := strings.LastIndex(v, ":"); i > 0 {
		port := v[i+1:]
		if port == "" || !allDigits(port) {
			return "", fmt.Sprintf("invalid port %q", port)
		}
		v = v[:i]
	}

	if strings.HasPrefix(v, "*.") {
		if !allowWildcard {
			return "", "wildcard entry rejected (pass -allow-wildcard to expand it)"
		}
		v = strings.TrimPrefix(v, "*.")
	}

	if !strings.Contains(v, ".") {
		if base == "" {
			return "", "bare label needs a base domain (-d)"
		}
		v = v + "." + base
	}

	v = models.NormalizeDomain(v)
	if err := ValidateHostname(v); err != nil {
		return "", err.Error()
	}
	return v, ""
}

func allDigits(s string) bool {
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return s != ""
}

// maxHostLen is the DNS limit; anything longer can never resolve.
const maxHostLen = 253

// ValidateHostname reports whether s is a syntactically usable DNS name.
func ValidateHostname(s string) error {
	if s == "" {
		return fmt.Errorf("empty hostname")
	}
	if len(s) > maxHostLen {
		return fmt.Errorf("hostname longer than %d characters", maxHostLen)
	}
	if strings.HasPrefix(s, ".") || strings.HasSuffix(s, ".") {
		return fmt.Errorf("hostname must not start or end with a dot")
	}
	if strings.Contains(s, "..") {
		return fmt.Errorf("hostname contains an empty label")
	}
	if !strings.Contains(s, ".") {
		return fmt.Errorf("hostname needs at least one dot")
	}
	for _, label := range strings.Split(s, ".") {
		if len(label) == 0 || len(label) > 63 {
			return fmt.Errorf("label %q has an invalid length", label)
		}
		if strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return fmt.Errorf("label %q must not start or end with a hyphen", label)
		}
		for _, r := range label {
			switch {
			case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-', r == '_':
			default:
				return fmt.Errorf("label %q contains an invalid character %q", label, r)
			}
		}
	}
	// The rightmost label must be alphabetic (TLDs are), otherwise this is
	// almost certainly a typo rather than a hostname.
	tld := s[strings.LastIndex(s, ".")+1:]
	for _, r := range tld {
		if r < 'a' || r > 'z' {
			if r < '0' || r > '9' {
				return fmt.Errorf("top-level label %q is not alphabetic", tld)
			}
		}
	}
	return nil
}
