package services

import (
	"encoding/json"
	"os"
	"testing"
)

// embeddedServices reads the shipped fingerprint database from disk. It lives
// at the repository root so operators can inspect and extend it; Go's embed
// directive cannot reach outside its own package directory.
func embeddedServices(t *testing.T) []byte {
	t.Helper()
	data, err := os.ReadFile("../../fingerprints/services.json")
	if err != nil {
		t.Fatalf("reading fingerprint database: %s", err)
	}
	return data
}

func TestEmbeddedFingerprintDatabaseIsValid(t *testing.T) {
	// The shipped database is the product's core data: if it fails to load the
	// tool is useless, so this is checked on every test run.
	reg, err := Load(embeddedServices(t))
	if err != nil {
		t.Fatalf("fingerprint database is invalid: %s", err)
	}
	if reg.Count() < 80 {
		t.Fatalf("fingerprint database regressed to %d entries", reg.Count())
	}

	// Every CNAME pattern must actually be detectable, otherwise an entry is
	// dead weight that silently produces false negatives.
	for _, fp := range reg.All() {
		for _, pattern := range fp.CNAME {
			if pattern == "" {
				continue
			}
			hit, _ := reg.Detect([]string{"probe." + pattern})
			if hit == nil {
				t.Fatalf("%q: pattern %q cannot detect itself", fp.Name, pattern)
			}
			if hit.Name != fp.Name {
				t.Fatalf("%q: pattern %q is shadowed by %q", fp.Name, pattern, hit.Name)
			}
			break
		}
	}
}

func TestEmbeddedFingerprintDatabaseHasUsableEvidence(t *testing.T) {
	reg, err := Load(embeddedServices(t))
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	for _, fp := range reg.All() {
		if fp.Claimable && len(fp.Fingerprints) == 0 && !fp.NXDomain {
			t.Errorf("%q is marked claimable but has no way to prove a takeover", fp.Name)
		}
	}
}

func TestNonClaimableProvidersCarryNoTakeoverFingerprints(t *testing.T) {
	// A provider with claimable:false must never be promoted to a finding on
	// the strength of a body fingerprint, because the verifier cannot act on
	// one. Leaving fingerprints on such an entry would suggest evidence that
	// leads nowhere.
	reg, err := Load(embeddedServices(t))
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	for _, fp := range reg.All() {
		if fp.Claimable {
			continue
		}
		if len(fp.Fingerprints) > 0 {
			t.Errorf("%q is not claimable but declares %d body fingerprint(s): %v",
				fp.Name, len(fp.Fingerprints), fp.Fingerprints)
		}
	}
}

func TestClaimableFlagIsExplicitOnEveryProvider(t *testing.T) {
	// The flag is what stops Cloudflare and Fastly being reported as
	// takeovers, so it has to be stated in the data rather than left to the
	// zero value of a missing field.
	var entries []map[string]any
	if err := json.Unmarshal(embeddedServices(t), &entries); err != nil {
		t.Fatalf("decoding fingerprint database: %s", err)
	}

	var claimable, notClaimable int
	for _, e := range entries {
		raw, ok := e["claimable"]
		if !ok {
			t.Errorf("%v omits the claimable field entirely", e["name"])
			continue
		}
		v, ok := raw.(bool)
		if !ok {
			t.Errorf("%v has a non-boolean claimable value: %v", e["name"], raw)
			continue
		}
		if v {
			claimable++
		} else {
			notClaimable++
		}
	}
	if notClaimable == 0 {
		t.Error("no provider is marked non-claimable; the field is probably being ignored")
	}
	if claimable == 0 {
		t.Error("no provider is marked claimable, which cannot be right")
	}
	t.Logf("%d claimable, %d not claimable", claimable, notClaimable)
}

func TestNoProviderIsClaimableWithoutAClaimPath(t *testing.T) {
	reg, err := Load(embeddedServices(t))
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	for _, fp := range reg.All() {
		if fp.Claimable && len(fp.Fingerprints) == 0 && !fp.NXDomain {
			t.Errorf("%q is claimable but has no body fingerprint and no dead-target path", fp.Name)
		}
	}
}
