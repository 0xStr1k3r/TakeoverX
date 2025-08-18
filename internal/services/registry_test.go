package services

import (
	"testing"

	"github.com/0xStr1k3r/TakeoverX/internal/models"
)

func testRegistry(t *testing.T) *Registry {
	t.Helper()
	reg, err := NewRegistry([]models.ServiceFingerprint{
		{Name: "AWS S3", CNAME: []string{"s3.amazonaws.com", ".s3-website"}, Claimable: true, Severity: "medium"},
		{Name: "Heroku", CNAME: []string{"herokuapp.com"}, NXDomain: true, Claimable: true, Severity: "high"},
		{Name: "GitHub Pages", IPRanges: []string{"185.199.108.0/22"}, Claimable: true, Severity: "medium"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	return reg
}

func TestDetectMatchesTailOfChain(t *testing.T) {
	reg := testRegistry(t)
	fp, hop := reg.Detect([]string{"a.example.com", "b.herokuapp.com"})
	if fp == nil || fp.Name != "Heroku" {
		t.Fatalf("fp: %v", fp)
	}
	if hop != "b.herokuapp.com" {
		t.Fatalf("hop: %s", hop)
	}
}

func TestDetectPrefersTerminalProvider(t *testing.T) {
	// A CNAME into a provider is sometimes re-pointed at another provider.
	// The terminal hop is the one that actually serves the name.
	reg := testRegistry(t)
	fp, _ := reg.Detect([]string{"x.s3.amazonaws.com", "y.herokuapp.com"})
	if fp == nil || fp.Name != "Heroku" {
		t.Fatalf("expected Heroku (terminal hop), got %v", fp)
	}
}

func TestDetectIsSuffixAnchoredNotSubstring(t *testing.T) {
	// The old detector used strings.Contains, so an attacker-controlled
	// CNAME containing the provider name was credited as a takeover.
	reg := testRegistry(t)
	fp, _ := reg.Detect([]string{"s3.amazonaws.com.attacker.example"})
	if fp != nil {
		t.Fatalf("substring match produced a false provider: %v", fp.Name)
	}
}

func TestDetectSingleLabelPatternMatchesLabelFamily(t *testing.T) {
	// ".s3-website" describes a DNS label family such as
	// "s3-website-us-east-1"; it must match within a label, at a boundary.
	reg := testRegistry(t)
	fp, _ := reg.Detect([]string{"bucket.s3-website-us-east-1.amazonaws.com"})
	if fp == nil || fp.Name != "AWS S3" {
		t.Fatalf("fp: %v", fp)
	}
}

func TestSingleLabelPatternDoesNotMatchMidLabel(t *testing.T) {
	reg := testRegistry(t)
	if fp, _ := reg.Detect([]string{"not-s3-website-ish.example.com"}); fp != nil {
		t.Fatalf("mid-label match must not count: %v", fp.Name)
	}
}

func TestDuplicatePatternPrefersStrongestEvidence(t *testing.T) {
	reg, err := NewRegistry([]models.ServiceFingerprint{
		{Name: "Generic", CNAME: []string{"cloudfront.net"}},
		{Name: "Specific", CNAME: []string{"cloudfront.net"}, Fingerprints: []string{"a", "b"}, NXDomain: true},
	})
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	fp, _ := reg.Detect([]string{"x.cloudfront.net"})
	if fp == nil || fp.Name != "Specific" {
		t.Fatalf("expected the stronger fingerprint, got %v", fp)
	}
}

func TestDetectCaseInsensitive(t *testing.T) {
	reg := testRegistry(t)
	if fp, _ := reg.Detect([]string{"APP.HEROKUAPP.COM"}); fp == nil {
		t.Fatal("detection must be case-insensitive")
	}
}

func TestDetectNoMatch(t *testing.T) {
	reg := testRegistry(t)
	if fp, _ := reg.Detect([]string{"host.internal.example.com"}); fp != nil {
		t.Fatalf("unexpected match: %v", fp.Name)
	}
	if fp, _ := reg.Detect(nil); fp != nil {
		t.Fatal("empty chain must not panic or match")
	}
}

func TestDetectIP(t *testing.T) {
	reg := testRegistry(t)
	if fp, _ := reg.DetectIP([]string{"185.199.108.153"}); fp == nil || fp.Name != "GitHub Pages" {
		t.Fatalf("ip detection failed: %v", fp)
	}
	if fp, _ := reg.DetectIP([]string{"8.8.8.8"}); fp != nil {
		t.Fatalf("unexpected ip match: %v", fp.Name)
	}
	if fp, _ := reg.DetectIP([]string{"not-an-ip"}); fp != nil {
		t.Fatal("malformed ip must not panic")
	}
}

func TestRegistryRejectsBadData(t *testing.T) {
	cases := map[string][]models.ServiceFingerprint{
		"missing name":  {{CNAME: []string{"x.com"}}},
		"no patterns":   {{Name: "X"}},
		"empty pattern": {{Name: "X", CNAME: []string{"  "}}},
		"bad cidr":      {{Name: "X", IPRanges: []string{"not-a-cidr"}}},
	}
	for label, fps := range cases {
		if _, err := NewRegistry(fps); err == nil {
			t.Errorf("%s: expected an error", label)
		}
	}
}

func TestLoadFromJSON(t *testing.T) {
	data := []byte(`[{"name":"S3","cname":["s3.amazonaws.com"],"fingerprints":["NoSuchBucket"],"nxdomain":false,"claimable":true}]`)
	reg, err := Load(data)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	if reg.Count() != 1 {
		t.Fatalf("count: %d", reg.Count())
	}
	if fp, _ := reg.Detect([]string{"b.s3.amazonaws.com"}); fp == nil {
		t.Fatal("loaded registry cannot detect")
	}
}

func TestLoadInvalidJSON(t *testing.T) {
	if _, err := Load([]byte("not json")); err == nil {
		t.Fatal("malformed json must error")
	}
}

func TestAllIsSorted(t *testing.T) {
	reg, err := NewRegistry([]models.ServiceFingerprint{
		{Name: "Zeta", CNAME: []string{"z.com"}},
		{Name: "Alpha", CNAME: []string{"a.com"}},
	})
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	all := reg.All()
	if all[0].Name != "Alpha" || all[1].Name != "Zeta" {
		t.Fatalf("All() must be sorted for stable reports: %v", all)
	}
}
