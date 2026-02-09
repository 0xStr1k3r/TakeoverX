package reporter

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/0xStr1k3r/TakeoverX/internal/models"
)

// Summary is the aggregate outcome of a scan.
type Summary struct {
	Total      int            `json:"total"`
	Vulnerable int            `json:"vulnerable"`
	High       int            `json:"high"`
	Medium     int            `json:"medium"`
	Safe       int            `json:"safe"`
	Unknown    int            `json:"unknown"`
	ByService  map[string]int `json:"by_service"`
	Duration   string         `json:"duration"`
	Started    string         `json:"started"`
}

// Report bundles everything a scan produces, so every output format renders
// the same data rather than each format recomputing and drifting.
type Report struct {
	Target      string              `json:"target"`
	Started     time.Time           `json:"started"`
	Duration    time.Duration       `json:"-"`
	DurationStr string              `json:"duration"`
	Mode        string              `json:"mode"`
	Results     []models.ScanResult `json:"results"`
	Summary     Summary             `json:"summary"`
	Rejected    int                 `json:"rejected_inputs"`
	Wildcard    bool                `json:"wildcard_dns"`
	Services    int                 `json:"providers_checked"`
	Notes       []string            `json:"notes,omitempty"`
}

// Build assembles a report and computes its summary.
func Build(target, mode string, results []models.ScanResult, started time.Time, dur time.Duration) *Report {
	rep := &Report{
		Target: target, Started: started, Duration: dur,
		DurationStr: dur.Round(time.Millisecond).String(),
		Mode:        mode, Results: results,
		Summary: Summary{
			Total: len(results), ByService: map[string]int{},
			Duration: fmtDuration(dur), Started: started.Format(time.RFC3339),
		},
	}
	// Findings first, most severe first, so a truncated terminal view still
	// shows what matters.
	sort.SliceStable(rep.Results, func(i, j int) bool {
		a, b := rep.Results[i], rep.Results[j]
		if a.Vulnerable() != b.Vulnerable() {
			return a.Vulnerable()
		}
		if a.Confidence != b.Confidence {
			return confidenceRank(a.Confidence) < confidenceRank(b.Confidence)
		}
		return a.Subdomain < b.Subdomain
	})
	for _, r := range rep.Results {
		switch r.Status {
		case string(models.StatusVulnerable):
			rep.Summary.Vulnerable++
			switch r.Confidence {
			case string(models.ConfidenceHigh):
				rep.Summary.High++
			case string(models.ConfidenceMedium):
				rep.Summary.Medium++
			}
			if r.Service != "" {
				rep.Summary.ByService[r.Service]++
			}
		case string(models.StatusSafe):
			rep.Summary.Safe++
		case string(models.StatusUnknown):
			rep.Summary.Unknown++
		}
	}
	return rep
}

func fmtDuration(d time.Duration) string { return d.Round(time.Millisecond).String() }

func confidenceRank(c string) int {
	switch c {
	case string(models.ConfidenceHigh):
		return 0
	case string(models.ConfidenceMedium):
		return 1
	}
	return 2
}

// ── formats ──────────────────────────────────────────────────────────────────

// Format names every supported output format.
const (
	FormatTable = "table"
	FormatJSON  = "json"
	FormatCSV   = "csv"
	FormatHTML  = "html"
	FormatSARIF = "sarif"
)

// Formats lists valid -o values.
func Formats() []string {
	return []string{FormatTable, FormatJSON, FormatCSV, FormatHTML, FormatSARIF}
}

// Write renders the report in the requested format. HTML and SARIF are written
// to a file rather than to a stream because they are documents.
func Write(w io.Writer, r *Report, format string) error {
	switch format {
	case FormatJSON:
		return writeJSON(w, r)
	case FormatCSV:
		return writeCSV(w, r)
	case FormatHTML:
		return WriteHTMLTo(w, r)
	case FormatSARIF:
		return writeSARIF(w, r)
	case FormatTable, "":
		return WriteTable(w, r)
	default:
		return fmt.Errorf("unknown output format %q (want one of %s)", format, strings.Join(Formats(), ", "))
	}
}

func writeJSON(w io.Writer, r *Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	// HTML escaping makes the report unreadable in a terminal and in diffs.
	enc.SetEscapeHTML(false)
	if err := enc.Encode(r); err != nil {
		return fmt.Errorf("encoding JSON report: %w", err)
	}
	return nil
}

var csvHeader = []string{
	"subdomain", "status", "confidence", "severity", "service",
	"record_type", "cname", "cname_chain", "ips", "matched_by",
	"reason", "remediation", "docs", "duration_ms",
}

func writeCSV(w io.Writer, r *Report) error {
	cw := csv.NewWriter(w)
	defer cw.Flush()
	if err := cw.Write(csvHeader); err != nil {
		return fmt.Errorf("writing CSV header: %w", err)
	}
	for _, s := range r.Results {
		row := []string{
			s.Subdomain, s.Status, s.Confidence, s.Severity, s.Service,
			s.RecordType, s.CNAME, s.CNAMEChain, strings.Join(s.IPs, " "),
			s.MatchedBy, s.Reason, s.Remediation, s.DocsURL,
			strconv.FormatFloat(s.Duration, 'f', 1, 64),
		}
		if err := cw.Write(row); err != nil {
			return fmt.Errorf("writing CSV row for %s: %w", s.Subdomain, err)
		}
	}
	cw.Flush()
	if err := cw.Error(); err != nil {
		return fmt.Errorf("flushing CSV: %w", err)
	}
	return nil
}

// WriteTable renders a colour-free, aligned summary. Colour is deliberately
// avoided so the output pipes cleanly into grep, awk and CI logs.
func WriteTable(w io.Writer, r *Report) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)

	fmt.Fprintln(tw, "SUBDOMAIN\tSTATUS\tCONFIDENCE\tSERVICE\tRECORD\tREASON")
	for _, s := range r.Results {
		if !s.Vulnerable() {
			continue
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n",
			s.Subdomain, s.Status, s.Confidence, s.Service, s.RecordType, truncate(s.Reason, 72))
	}
	if err := tw.Flush(); err != nil {
		return fmt.Errorf("writing table: %w", err)
	}
	writeSummaryLine(w, r)
	return nil
}

func writeSummaryLine(w io.Writer, r *Report) {
	fmt.Fprintf(w, "\n%d scanned | %d vulnerable (%d high, %d medium) | %d safe | %d unknown | %s\n",
		r.Summary.Total, r.Summary.Vulnerable, r.Summary.High, r.Summary.Medium,
		r.Summary.Safe, r.Summary.Unknown, r.DurationStr)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	if n <= 1 {
		return s[:n]
	}
	return s[:n-1] + "…"
}

// ── SARIF ────────────────────────────────────────────────────────────────────

// sarifDoc is the minimal SARIF 2.1.0 shape that CI scanners accept.
type sarifDoc struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	InformationURI string      `json:"informationUri"`
	Version        string      `json:"version,omitempty"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string       `json:"id"`
	Name             string       `json:"name"`
	ShortDescription sarifMessage `json:"shortDescription"`
}

type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   sarifMessage    `json:"message"`
	Locations []sarifLocation `json:"locations"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifLocation struct {
	PhysicalLocation struct {
		ArtifactLocation struct {
			URI string `json:"uri"`
		} `json:"artifactLocation"`
	} `json:"physicalLocation"`
}

// severityLevel maps our confidence grades onto SARIF levels. SARIF has no
// HIGH/MEDIUM, so HIGH maps to "error" — the only level most CI gates on.
func severityLevel(r models.ScanResult) string {
	if !r.Vulnerable() {
		return "note"
	}
	if r.Confidence == string(models.ConfidenceHigh) || r.Severity == "critical" {
		return "error"
	}
	return "warning"
}

func writeSARIF(w io.Writer, r *Report) error {
	doc := sarifDoc{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Version: "2.1.0",
	}
	run := sarifRun{}
	run.Tool.Driver.Name = "TakeoverX"
	run.Tool.Driver.InformationURI = "https://github.com/0xStr1k3r/TakeoverX"

	seen := map[string]bool{}
	for _, s := range r.Results {
		if s.Status == "" {
			continue
		}
		id := "takeover/" + strings.ReplaceAll(strings.ToLower(strings.ReplaceAll(s.Service, " ", "-")), "/", "-")
		if !seen[id] {
			seen[id] = true
			rule := sarifRule{ID: id, Name: s.Service}
			rule.ShortDescription.Text = "Subdomain takeover risk on " + s.Service
			run.Tool.Driver.Rules = append(run.Tool.Driver.Rules, rule)
		}
		res := sarifResult{RuleID: id, Level: severityLevel(s)}
		res.Message.Text = strings.TrimSpace(s.Reason + " — " + s.Remediation)
		loc := sarifLocation{}
		loc.PhysicalLocation.ArtifactLocation.URI = s.Subdomain
		res.Locations = []sarifLocation{loc}
		run.Results = append(run.Results, res)
	}
	doc.Runs = []sarifRun{run}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(doc); err != nil {
		return fmt.Errorf("encoding SARIF report: %w", err)
	}
	return nil
}

// SaveFile writes a report document to disk, creating parent directories.
func SaveFile(r *Report, format, path string) error {
	if dir := filepath.Dir(path); dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return fmt.Errorf("creating output directory %q: %w", dir, err)
		}
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("creating %q: %w", path, err)
	}
	defer f.Close()
	if err := Write(f, r, format); err != nil {
		return err
	}
	return f.Close()
}

// Save mirrors the previous package-level API used by the CLI.
func Save(results []models.ScanResult, format, path string) error {
	return SaveFile(Build("target", "", results, time.Now(), 0), format, path)
}

// PrintJSON mirrors the previous API: JSON straight to stdout.
func PrintJSON(w io.Writer, results []models.ScanResult) error {
	return Write(w, Build("target", "", results, time.Now(), 0), FormatJSON)
}

// PrintTable mirrors the previous API.
func PrintTable(w io.Writer, results []models.ScanResult) error {
	return Write(w, Build("target", "", results, time.Now(), 0), FormatTable)
}

// PrintCSV mirrors the previous API.
func PrintCSV(w io.Writer, results []models.ScanResult) error {
	return Write(w, Build("target", "", results, time.Now(), 0), FormatCSV)
}

// WriteHTML mirrors the previous API.
func WriteHTML(results []models.ScanResult, path string) error {
	return SaveFile(Build("target", "", results, time.Now(), 0), FormatHTML, path)
}
