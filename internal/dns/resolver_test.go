package dns

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/0xStr1k3r/TakeoverX/internal/models"
)

type fakeResolver struct {
	cnames  map[string]string
	addrs   map[string][]string
	failCN  bool
	failAll map[string]bool
}

func (f *fakeResolver) LookupCNAME(_ context.Context, host string) (string, error) {
	if f.failAll[host] {
		return "", errors.New("no such host")
	}
	if v, ok := f.cnames[host]; ok {
		return v, nil
	}
	return "", errors.New("no such host")
}
func (f *fakeResolver) LookupHost(_ context.Context, host string) ([]string, error) {
	if f.failAll[host] {
		return nil, errors.New("no such host")
	}
	if v, ok := f.addrs[host]; ok {
		return v, nil
	}
	return nil, errors.New("no such host")
}

func withFake(t *testing.T, f *fakeResolver) {
	t.Helper()
	old := resolver
	SetResolver(f)
	ResetCache()
	t.Cleanup(func() { SetResolver(old); ResetCache() })
}

func TestResolveCNAMEChain(t *testing.T) {
	withFake(t, &fakeResolver{
		cnames: map[string]string{
			"a.example.com":      "b.s3.amazonaws.com.",
			"b.s3.amazonaws.com": "s3-1-w.amazonaws.com.",
		},
		addrs: map[string][]string{
			"a.example.com":        {"1.2.3.4"},
			"s3-1-w.amazonaws.com": {"52.1.2.3"},
		},
		failAll: map[string]bool{},
	})
	r := Resolve("a.example.com")
	if r.RecordType != models.RecordCNAME {
		t.Fatalf("record type: %s", r.RecordType)
	}
	if len(r.CNAMEChain) != 2 {
		t.Fatalf("chain: %v", r.CNAMEChain)
	}
	if r.CNAME != "b.s3.amazonaws.com" {
		t.Fatalf("primary cname: %s", r.CNAME)
	}
	if r.IsDead {
		t.Fatal("live chain must not be dead")
	}
}

func TestResolveDeadTarget(t *testing.T) {
	withFake(t, &fakeResolver{
		cnames:  map[string]string{"gone.example.com": "gone.herokuapp.com."},
		addrs:   map[string][]string{},
		failAll: map[string]bool{"gone.herokuapp.com": true},
	})
	r := Resolve("gone.example.com")
	if !r.IsDead {
		t.Fatal("chain to a non-resolving target must be IsDead")
	}
}

func TestResolveNXDomain(t *testing.T) {
	withFake(t, &fakeResolver{
		cnames:  map[string]string{},
		addrs:   map[string][]string{},
		failAll: map[string]bool{"nope.example.com": true},
	})
	r := Resolve("nope.example.com")
	if !r.NXDomain {
		t.Fatal("expected NXDOMAIN")
	}
	if r.RecordType != models.RecordNone {
		t.Fatalf("record type: %s", r.RecordType)
	}
}

func TestResolveARecord(t *testing.T) {
	withFake(t, &fakeResolver{
		cnames:  map[string]string{},
		addrs:   map[string][]string{"pages.example.com": {"185.199.108.153"}},
		failAll: map[string]bool{},
	})
	r := Resolve("pages.example.com")
	if r.RecordType != models.RecordA {
		t.Fatalf("record type: %s", r.RecordType)
	}
	if len(r.IPs) != 1 || r.IPs[0] != "185.199.108.153" {
		t.Fatalf("ips: %v", r.IPs)
	}
}

func TestWildcardDetection(t *testing.T) {
	old := resolver
	SetResolver(wildcardResolver{})
	ResetCache()
	defer func() { SetResolver(old); ResetCache() }()
	if !WildcardActive("example.com") {
		t.Fatal("expected wildcard to be detected")
	}
}

type wildcardResolver struct{}

func (wildcardResolver) LookupCNAME(context.Context, string) (string, error) {
	return "", errors.New("no such host")
}
func (wildcardResolver) LookupHost(context.Context, string) ([]string, error) {
	return []string{"6.6.6.6"}, nil
}

func TestNoWildcardForBareLabel(t *testing.T) {
	old := resolver
	SetResolver(wildcardResolver{})
	ResetCache()
	defer func() { SetResolver(old); ResetCache() }()
	if WildcardActive("localhost") {
		t.Fatal("bare label must not be wildcard-probed")
	}
}

func TestCaching(t *testing.T) {
	calls := 0
	base := &countingResolver{inner: wildcardResolver{}, onHost: func() { calls++ }}
	old := resolver
	SetResolver(base)
	ResetCache()
	defer func() { SetResolver(old); ResetCache() }()
	Resolve("a.example.com")
	Resolve("a.example.com")
	if calls != 1 {
		t.Fatalf("expected cache hit (1 lookup), got %d", calls)
	}
	if CachedCount() == 0 {
		t.Fatal("cache should hold the result")
	}
}

type countingResolver struct {
	inner  Resolver
	onHost func()
}

func (c *countingResolver) LookupCNAME(ctx context.Context, h string) (string, error) {
	return c.inner.LookupCNAME(ctx, h)
}
func (c *countingResolver) LookupHost(ctx context.Context, h string) ([]string, error) {
	c.onHost()
	return c.inner.LookupHost(ctx, h)
}

func TestDedupesTrailingDot(t *testing.T) {
	withFake(t, &fakeResolver{
		cnames:  map[string]string{"x.example.com": "y.example.net."},
		addrs:   map[string][]string{"y.example.net": {"9.9.9.9"}},
		failAll: map[string]bool{},
	})
	r := Resolve("x.example.com.")
	if len(r.CNAMEChain) != 1 || strings.HasSuffix(r.CNAMEChain[0], ".") {
		t.Fatalf("chain not normalized: %v", r.CNAMEChain)
	}
}
