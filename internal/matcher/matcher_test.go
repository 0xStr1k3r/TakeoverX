package matcher

import (
	"testing"

	"github.com/0xStr1k3r/TakeoverX/internal/models"
)

func TestMatchBody(t *testing.T) {
	fp := &models.ServiceFingerprint{Fingerprints: []string{"NoSuchBucket", "NoSuchKey"}}

	ok, which := Match(fp, "<Error><Code>NoSuchBucket</Code></Error>")
	if !ok || which != "NoSuchBucket" {
		t.Fatalf("got ok=%v which=%q", ok, which)
	}
	if ok, _ := Match(fp, "a perfectly normal page"); ok {
		t.Fatal("unexpected match on unrelated body")
	}
}

func TestMatchEmptyFingerprintNeverMatchesEverything(t *testing.T) {
	// A blank entry in the database used to make every provider match any body.
	fp := &models.ServiceFingerprint{Fingerprints: []string{""}}
	if ok, _ := Match(fp, "anything at all"); ok {
		t.Fatal("an empty fingerprint must never match")
	}
}

func TestMatchEmptyBody(t *testing.T) {
	fp := &models.ServiceFingerprint{Fingerprints: []string{"NoSuchBucket"}}
	if ok, _ := Match(fp, ""); ok {
		t.Fatal("an empty body must not match")
	}
}

func TestMatchCaseSensitivity(t *testing.T) {
	fp := &models.ServiceFingerprint{Fingerprints: []string{"NoSuchBucket"}}
	if ok, _ := Match(fp, "nosuchbucket"); ok {
		t.Fatal("body matching must be case-sensitive; provider pages are exact")
	}
}

func TestMatchHeaders(t *testing.T) {
	fp := &models.ServiceFingerprint{Name: "AmazonS3", HeaderFingerprints: []string{"cloudfront"}}
	h := map[string]string{"Server": "cloudfront", "Content-Type": "text/html"}

	ok, which := MatchHeaders(fp, h)
	if !ok || which != "cloudfront" {
		t.Fatalf("got ok=%v which=%q", ok, which)
	}
}

func TestMatchHeadersByServiceName(t *testing.T) {
	fp := &models.ServiceFingerprint{Name: "cloudflare"}
	h := map[string]string{"Server": "cloudflare"}
	if ok, _ := MatchHeaders(fp, h); !ok {
		t.Fatal("expected a match on the service name")
	}
}

func TestMatchHeadersCaseInsensitive(t *testing.T) {
	fp := &models.ServiceFingerprint{Name: "AmazonS3"}
	h := map[string]string{"server": "AMAZONS3"}
	if ok, _ := MatchHeaders(fp, h); !ok {
		t.Fatal("header names and values must match case-insensitively")
	}
}

func TestMatchHeadersIgnoresUnrelatedHeaders(t *testing.T) {
	// Matching the service name against every header produced nonsense: a
	// Cache-Control of "cloudflare" is not a Cloudflare fingerprint.
	fp := &models.ServiceFingerprint{Name: "cloudflare"}
	h := map[string]string{
		"Cache-Control": "cloudflare",
		"Content-Type":  "cloudflare",
		"Set-Cookie":    "cloudflare",
	}
	if ok, _ := MatchHeaders(fp, h); ok {
		t.Fatal("non-identifying headers must not match")
	}
}

func TestMatchHeadersAcceptsKnownIdentifyingHeaders(t *testing.T) {
	fp := &models.ServiceFingerprint{Name: "anything", HeaderFingerprints: []string{"fingerprint-value"}}
	for _, name := range []string{
		"Server", "X-Powered-By", "Via", "X-Served-By",
		"X-Amz-Request-Id", "X-Amz-Id-2", "X-Github-Request-Id",
		"X-Vercel-Id", "X-Nf-Request-Id", "X-Netlify-Request-Id",
		"Fly-Request-Id", "X-Render-Origin-Server",
	} {
		h := map[string]string{name: "fingerprint-value"}
		if ok, _ := MatchHeaders(fp, h); !ok {
			t.Errorf("header %q should be treated as identifying", name)
		}
	}
}

func TestMatchHeadersNilFingerprints(t *testing.T) {
	fp := &models.ServiceFingerprint{Name: "x", Fingerprints: []string{"nothing"}}
	if ok, _ := MatchHeaders(fp, map[string]string{"Server": "nothing"}); ok {
		t.Fatal("body fingerprints must not leak into header matching")
	}
}

func TestMatchHeadersEmptyInput(t *testing.T) {
	fp := &models.ServiceFingerprint{Name: "x", Fingerprints: []string{"y"}}
	if ok, _ := MatchHeaders(fp, nil); ok {
		t.Fatal("nil headers must not match")
	}
	if ok, _ := MatchHeaders(fp, map[string]string{"Server": ""}); ok {
		t.Fatal("an empty header value must not match")
	}
}

func TestIsIdentifyingHeader(t *testing.T) {
	if isIdentifyingHeader("server") != true {
		t.Error("server should be identifying")
	}
	if isIdentifyingHeader("content-type") != false {
		t.Error("content-type should not be identifying")
	}
	if isIdentifyingHeader("") != false {
		t.Error("empty name should not be identifying")
	}
}
