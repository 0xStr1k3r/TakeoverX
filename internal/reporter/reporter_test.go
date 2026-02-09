package reporter

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/0xStr1k3r/TakeoverX/internal/models"
)

func sampleResults() []models.ScanResult {
	return []models.ScanResult{
		{Subdomain: "cdn.example.com", Status: "VULNERABLE", Confidence: "HIGH", Service: "AWS S3",
			RecordType: "CNAME", CNAMEChain: "old.s3.amazonaws.com", Severity: "high",
			Reason: "AWS S3 reports the resource is unclaimed", Remediation: "Remove the dangling CNAME",
			DocsURL: "https://docs.aws.amazon.com/", MatchedBy: "old.s3.amazonaws.com"},
		{Subdomain: "shop.example.com", Status: "VULNERABLE", Confidence: "MEDIUM", Service: "Shopify",
			RecordType: "CNAME", CNAMEChain: "shop.myshopify.com", Severity: "critical",
			Reason: "Shopify signature in response headers"},
		{Subdomain: "www.example.com", Status: "SAFE", Confidence: "LOW", Service: "AWS S3", Reason: "serving content"},
		{Subdomain: "blog.example.com", Status: "UNKNOWN", Confidence: "LOW", Reason: "probe failed"},
	}
}

func testReport() *Report {
	return Build("example.com", "scan", sampleResults(), time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC), 7*time.Second)
}

func TestBuildSummarises(t *testing.T) {
	r := testReport()
	if r.Summary.Total != 4 {
		t.Fatalf("total: %d", r.Summary.Total)
	}
	if r.Summary.Vulnerable != 2 {
		t.Fatalf("vulnerable: %d", r.Summary.Vulnerable)
	}
	if r.Summary.High != 1 || r.Summary.Medium != 1 {
		t.Fatalf("confidence split: high=%d medium=%d", r.Summary.High, r.Summary.Medium)
	}
	if r.Summary.Safe != 1 || r.Summary.Unknown != 1 {
		t.Fatalf("safe=%d unknown=%d", r.Summary.Safe, r.Summary.Unknown)
	}
	if len(r.Summary.ByService) != 2 {
		t.Fatalf("by service: %v", r.Summary.ByService)
	}
}

func TestBuildSortsFindingsFirst(t *testing.T) {
	r := testReport()
	for i := 0; i < r.Summary.Vulnerable; i++ {
		if !r.Results[i].Vulnerable() {
			t.Fatalf("finding not first at index %d: %+v", i, r.Results[i])
		}
	}
	if r.Results[0].Confidence != "HIGH" {
		t.Fatalf("HIGH confidence must sort before MEDIUM: %s", r.Results[0].Confidence)
	}
}

func TestBuildStableOrder(t *testing.T) {
	// Same input must produce the same ordering every run.
	a := Build("x", "s", sampleResults(), time.Now(), time.Second)
	b := Build("x", "s", sampleResults(), time.Now(), time.Second)
	for i := range a.Results {
		if a.Results[i].Subdomain != b.Results[i].Subdomain {
			t.Fatalf("unstable ordering at %d", i)
		}
	}
}

func TestWriteJSONRoundTrips(t *testing.T) {
	var buf bytes.Buffer
	if err := Write(&buf, testReport(), FormatJSON); err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	var back Report
	if err := json.Unmarshal(buf.Bytes(), &back); err != nil {
		t.Fatalf("report is not valid JSON: %s", err)
	}
	if back.Summary.Vulnerable != 2 {
		t.Fatalf("round trip lost data: %+v", back.Summary)
	}
	if !strings.Contains(buf.String(), "cdn.example.com") {
		t.Fatal("finding missing from JSON")
	}
}

func TestWriteJSONDoesNotEscapeHTML(t *testing.T) {
	r := Build("x", "s", []models.ScanResult{{
		Subdomain: "a.example.com", Status: "VULNERABLE", Reason: "script <b>tag</b>",
	}}, time.Now(), time.Second)
	var buf bytes.Buffer
	if err := Write(&buf, r, FormatJSON); err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	if strings.Contains(buf.String(), `\u003cb\u003e`) {
		t.Fatal("HTML entities make the report unreadable and break diffs")
	}
}

func TestWriteCSVIsWellFormed(t *testing.T) {
	var buf bytes.Buffer
	if err := Write(&buf, testReport(), FormatCSV); err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	rows, err := csv.NewReader(&buf).ReadAll()
	if err != nil {
		t.Fatalf("CSV is malformed: %s", err)
	}
	if len(rows) != 5 { // header + 4 results
		t.Fatalf("row count: %d", len(rows))
	}
	if len(rows[0]) != len(csvHeader) {
		t.Fatalf("header width %d != %d", len(rows[0]), len(csvHeader))
	}
	for _, row := range rows {
		if len(row) != len(csvHeader) {
			t.Fatalf("ragged row: %v", row)
		}
	}
}

func TestWriteCSVEscapesCommas(t *testing.T) {
	r := Build("x", "s", []models.ScanResult{{
		Subdomain: "a.example.com", Status: "VULNERABLE",
		Reason: "one, two, three", Remediation: "do \"this\"",
	}}, time.Now(), time.Second)
	var buf bytes.Buffer
	if err := Write(&buf, r, FormatCSV); err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	rows, _ := csv.NewReader(&buf).ReadAll()
	if rows[1][10] != "one, two, three" {
		t.Fatalf("comma field mangled: %q", rows[1][10])
	}
}

func TestWriteTableShowsOnlyFindings(t *testing.T) {
	var buf bytes.Buffer
	if err := Write(&buf, testReport(), FormatTable); err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	out := buf.String()
	if !strings.Contains(out, "cdn.example.com") || !strings.Contains(out, "shop.example.com") {
		t.Fatalf("findings missing from table:\n%s", out)
	}
	if strings.Contains(out, "www.example.com") {
		t.Fatalf("safe results must not clutter the table:\n%s", out)
	}
	if !strings.Contains(out, "4 scanned") {
		t.Fatalf("summary line missing:\n%s", out)
	}
}

func TestWriteSARIFIsValid(t *testing.T) {
	var buf bytes.Buffer
	if err := Write(&buf, testReport(), FormatSARIF); err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("SARIF is not valid JSON: %s", err)
	}
	if doc["version"] != "2.1.0" {
		t.Fatalf("SARIF version: %v", doc["version"])
	}
	runs := doc["runs"].([]any)
	if len(runs) != 1 {
		t.Fatalf("runs: %d", len(runs))
	}
	results := runs[0].(map[string]any)["results"].([]any)
	if len(results) != 4 {
		t.Fatalf("every result should be present, got %d", len(results))
	}
	levels := map[string]int{}
	for _, r := range results {
		levels[r.(map[string]any)["level"].(string)]++
	}
	if levels["error"] == 0 {
		t.Fatalf("a HIGH confidence finding must map to the error level: %v", levels)
	}
}

func TestWriteHTMLIsSelfContained(t *testing.T) {
	var buf bytes.Buffer
	if err := Write(&buf, testReport(), FormatHTML); err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	out := buf.String()
	if !strings.HasPrefix(out, "<!DOCTYPE html>") {
		t.Fatal("HTML output is not a document")
	}
	for _, bad := range []string{"http://cdn", "https://fonts.", "<script src="} {
		if strings.Contains(out, bad) {
			t.Fatalf("report references an external resource (%q); it must work offline", bad)
		}
	}
	if !strings.Contains(out, "cdn.example.com") {
		t.Fatal("finding missing from HTML")
	}
}

func TestWriteRejectsUnknownFormat(t *testing.T) {
	var buf bytes.Buffer
	err := Write(&buf, testReport(), "xml")
	if err == nil {
		t.Fatal("unknown format must error")
	}
	if !strings.Contains(err.Error(), "table") {
		t.Fatalf("error should list valid formats: %s", err)
	}
}

func TestWriteAllFormatsSucceed(t *testing.T) {
	for _, f := range Formats() {
		var buf bytes.Buffer
		if err := Write(&buf, testReport(), f); err != nil {
			t.Errorf("format %s failed: %s", f, err)
		}
		if buf.Len() == 0 {
			t.Errorf("format %s produced no output", f)
		}
	}
}

func TestWriteEmptyReportIsHonest(t *testing.T) {
	// "Nothing found" must render clearly rather than looking broken.
	r := Build("example.com", "scan", nil, time.Now(), time.Second)
	var buf bytes.Buffer
	if err := Write(&buf, r, FormatTable); err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	if !strings.Contains(buf.String(), "0 scanned") {
		t.Fatalf("empty summary missing: %s", buf.String())
	}
}

func TestFindingsOnly(t *testing.T) {
	got := FindingsOnly(testReport())
	if len(got.Results) != 2 {
		t.Fatalf("got %d", len(got.Results))
	}
	for _, s := range got.Results {
		if !s.Vulnerable() {
			t.Fatalf("non-finding survived the filter: %+v", s)
		}
	}
	if got.Summary.High != 1 || got.Summary.Medium != 1 {
		t.Fatalf("counts not recomputed: high=%d medium=%d", got.Summary.High, got.Summary.Medium)
	}
}

func TestFindingsOnlyDoesNotMutateOriginal(t *testing.T) {
	orig := testReport()
	before := len(orig.Results)
	FindingsOnly(orig)
	if len(orig.Results) != before {
		t.Fatal("FindingsOnly mutated the original report")
	}
}

func TestSaveFileCreatesDirectories(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/nested/deeper/report.json"
	if err := SaveFile(testReport(), FormatJSON, path); err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("file not written: %s", err)
	}
}

func TestSaveFileRejectsBadPath(t *testing.T) {
	if err := SaveFile(testReport(), FormatJSON, "/proc/nope/report.json"); err == nil {
		t.Fatal("an unwritable path must error, not panic")
	}
}

func TestTruncate(t *testing.T) {
	if got := truncate("hello", 10); got != "hello" {
		t.Fatalf("got %q", got)
	}
	if got := truncate("hello world", 6); got != "hello…" {
		t.Fatalf("got %q", got)
	}
	if got := truncate("hello", 0); got != "" {
		t.Fatalf("truncating to zero must yield an empty string, got %q", got)
	}
	if got := truncate("hello", 1); got != "h" {
		t.Fatalf("got %q", got)
	}
}

func TestSeverityLevel(t *testing.T) {
	cases := []struct {
		r    models.ScanResult
		want string
	}{
		{models.ScanResult{Status: "VULNERABLE", Confidence: "HIGH"}, "error"},
		{models.ScanResult{Status: "VULNERABLE", Confidence: "MEDIUM"}, "warning"},
		{models.ScanResult{Status: "VULNERABLE", Confidence: "MEDIUM", Severity: "critical"}, "error"},
		{models.ScanResult{Status: "SAFE"}, "note"},
		{models.ScanResult{Status: "UNKNOWN"}, "note"},
	}
	for _, c := range cases {
		if got := severityLevel(c.r); got != c.want {
			t.Errorf("severityLevel(%+v) = %s, want %s", c.r, got, c.want)
		}
	}
}

func TestFindingsOnlySerialisesAsEmptyArray(t *testing.T) {
	// nil slices marshal to JSON null. Consumers iterating results[] must not
	// have to guard against that, so an empty result set stays an array.
	r := Build("example.com", "scan", []models.ScanResult{
		{Subdomain: "a.example.com", Status: "SAFE"},
	}, time.Now(), time.Second)

	var buf bytes.Buffer
	if err := Write(&buf, FindingsOnly(r), FormatJSON); err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	if !strings.Contains(buf.String(), `"results": []`) {
		t.Fatalf("expected an empty array, got:\n%s", buf.String())
	}
}

func TestOnlyFindingsIsSeparateFromVerbose(t *testing.T) {
	// FindingsOnly must never mutate or alias the source slice, otherwise a
	// filtered stdout view would empty the file view too.
	r := testReport()
	filtered := FindingsOnly(r)
	if len(r.Results) != 4 {
		t.Fatalf("source report was mutated: %d results", len(r.Results))
	}
	if len(filtered.Results) != 2 {
		t.Fatalf("filtered report: %d", len(filtered.Results))
	}
	filtered.Results[0] = models.ScanResult{Subdomain: "clobbered"}
	if r.Results[0].Subdomain == "clobbered" {
		t.Fatal("FindingsOnly aliases the original slice")
	}
}
