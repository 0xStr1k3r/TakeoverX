package loader

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeFile(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "list.txt")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatalf("writing fixture: %s", err)
	}
	return p
}

func TestLoadSingleDomain(t *testing.T) {
	res, err := Load("Example.COM.", "", nil, Options{})
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	if len(res.Domains) != 1 || res.Domains[0] != "example.com" {
		t.Fatalf("domains: %v", res.Domains)
	}
}

func TestLoadStripsSchemeAndTrailingSlash(t *testing.T) {
	res, err := Load("https://api.example.com/", "", nil, Options{})
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	if res.Domains[0] != "api.example.com" {
		t.Fatalf("got %q", res.Domains[0])
	}
}

func TestLoadStripsPort(t *testing.T) {
	// Previously the port survived into the DNS lookup and broke it.
	res, err := Load("api.example.com:8443", "", nil, Options{})
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	if res.Domains[0] != "api.example.com" {
		t.Fatalf("port not stripped: %q", res.Domains[0])
	}
}

func TestLoadRejectsBadInputWithReasons(t *testing.T) {
	in := strings.Join([]string{
		"good.example.com",
		"",
		"# a comment",
		"http://ok.example.com",
		"api.example.com/path",
		"user:pass@example.com",
		"has space.example.com",
		"bad..example.com",
		"-lead.example.com",
		"trail-.example.com",
		"under_score.example.com",
		"x.example.com:port",
		"localhost",
		strings.Repeat("a", 70) + ".example.com",
	}, "\n")

	res, err := Load("", writeFile(t, in), nil, Options{})
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	if len(res.Domains) != 3 {
		t.Fatalf("expected 3 usable hosts, got %v", res.Domains)
	}
	if len(res.Rejected) == 0 {
		t.Fatal("rejections must be reported, not silently swallowed")
	}
	for _, r := range res.Rejected {
		if r.Reason == "" {
			t.Fatalf("rejection without a reason: %+v", r)
		}
	}
}

func TestLoadDeduplicates(t *testing.T) {
	in := "a.example.com\na.example.com\nA.EXAMPLE.COM.\nb.example.com\n"
	res, err := Load("", writeFile(t, in), nil, Options{})
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	if len(res.Domains) != 2 {
		t.Fatalf("expected 2 unique hosts, got %v", res.Domains)
	}
	if res.Duplicate != 2 {
		t.Fatalf("duplicates counted: %d", res.Duplicate)
	}
}

func TestLoadBareLabelNeedsBase(t *testing.T) {
	if _, err := Load("api", "", nil, Options{}); err == nil {
		t.Fatal("a bare label without a base must be an error")
	}
	res, err := Load("api", "", nil, Options{Base: "example.com"})
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	if res.Domains[0] != "api.example.com" {
		t.Fatalf("got %q", res.Domains[0])
	}
}

func TestLoadWildcardRequiresOptIn(t *testing.T) {
	if _, err := Load("*.example.com", "", nil, Options{}); err == nil {
		t.Fatal("wildcard must be rejected by default")
	}
	res, err := Load("*.example.com", "", nil, Options{AllowWildcardLines: true})
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	if res.Domains[0] != "example.com" {
		t.Fatalf("got %q", res.Domains[0])
	}
}

func TestLoadFromStdin(t *testing.T) {
	res, err := Load("", "", strings.NewReader("x.example.com\ny.example.com\n"), Options{})
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	if len(res.Domains) != 2 {
		t.Fatalf("got %v", res.Domains)
	}
}

func TestLoadMissingFileIsClearError(t *testing.T) {
	_, err := Load("", "/definitely/not/here.txt", nil, Options{})
	if err == nil {
		t.Fatal("missing wordlist must error")
	}
	if !strings.Contains(err.Error(), "cannot read wordlist") {
		t.Fatalf("error should name the problem: %s", err)
	}
}

func TestLoadEmptyFileIsClearError(t *testing.T) {
	_, err := Load("", writeFile(t, "# only comments\n\n"), nil, Options{})
	if err == nil {
		t.Fatal("an all-comment wordlist must error")
	}
	if !strings.Contains(err.Error(), "no usable hostnames") {
		t.Fatalf("error should explain why: %s", err)
	}
}

func TestLoadNoInputIsClearError(t *testing.T) {
	_, err := Load("", "", nil, Options{})
	if err == nil || !strings.Contains(err.Error(), "no valid hostnames") {
		t.Fatalf("expected a helpful error, got %v", err)
	}
}

func TestValidateHostname(t *testing.T) {
	valid := []string{"example.com", "a.b.example.com", "xn--bcher-kva.example.com", "_dmarc.example.com"}
	for _, v := range valid {
		if err := ValidateHostname(v); err != nil {
			t.Errorf("ValidateHostname(%q) = %s, want nil", v, err)
		}
	}
	invalid := []string{"", "example", "example..com", ".example.com", "example.com.", "ex ample.com", "a-.com"}
	for _, v := range invalid {
		if err := ValidateHostname(v); err == nil {
			t.Errorf("ValidateHostname(%q) = nil, want an error", v)
		}
	}
}

func TestLoadHandlesVeryLongLine(t *testing.T) {
	// A scanner buffer overrun must produce an error, not a panic.
	long := strings.Repeat("a", 2*1024*1024) + ".example.com"
	_, err := Load("", "", strings.NewReader(long+"\nok.example.com\n"), Options{})
	if err == nil {
		t.Fatal("an oversized line must be reported as an error")
	}
}
