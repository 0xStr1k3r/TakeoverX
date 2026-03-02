package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/0xStr1k3r/TakeoverX/internal/discovery"
	"github.com/0xStr1k3r/TakeoverX/internal/dns"
	"github.com/0xStr1k3r/TakeoverX/internal/httpclient"
	"github.com/0xStr1k3r/TakeoverX/internal/loader"
	"github.com/0xStr1k3r/TakeoverX/internal/matcher"
	"github.com/0xStr1k3r/TakeoverX/internal/models"
	"github.com/0xStr1k3r/TakeoverX/internal/reporter"
	"github.com/0xStr1k3r/TakeoverX/internal/services"
	"github.com/0xStr1k3r/TakeoverX/internal/validation"
)

// Version is overridable at build time with -ldflags "-X main.version=…".
var version = "1.0.0"

// FingerprintsData is injected from main.go via the embed directive.
var FingerprintsData []byte

// Exit codes. A scanner has to be usable in CI, so findings and operational
// failures must be distinguishable.
const (
	exitClean  = 0 // nothing actionable found
	exitFound  = 1 // at least one finding at or above the threshold
	exitFailed = 2 // the scan could not be completed
)

type options struct {
	wordlist     string
	domain       string
	bruteforce   string
	passive      bool
	stdin        bool
	concurrent   int
	out          string
	report       string
	save         string
	verbose      bool
	explain      bool
	quiet        bool
	timeout      int
	rate         int
	repeats      int
	noVerify     bool
	proxy        string
	failOn       string
	exitZero     bool
	onlyFindings bool
	maxNames     int
	defaultWords bool
}

var opts options

var rootCmd = &cobra.Command{
	Use:   "takeoverx",
	Short: "TakeoverX — subdomain takeover scanner",
	Long: banner() + `
Finds subdomains whose DNS still points at a cloud service that no longer
claims them, which lets anyone else register the name and serve content
under your domain.

Only scan assets you have explicit written authorisation to test.`,
	Version:       version,
	SilenceUsage:  true, // usage is noise once RunE has started failing
	SilenceErrors: true, // Execute prints errors once, with our own formatting
	RunE:          run,
	Args:          cobra.NoArgs,
}

func init() {
	// Pre-register "version" without a shorthand so cobra does not claim "-v",
	// which conventionally means verbose. Registering it first also lets cobra
	// keep its built-in --version behaviour.
	rootCmd.Flags().Bool("version", false, "Print the version and exit")
	rootCmd.SetVersionTemplate("takeoverx {{.Version}}\n")

	f := rootCmd.Flags()
	f.StringVarP(&opts.domain, "domain", "d", "", "Base domain or single subdomain to check")
	f.StringVarP(&opts.wordlist, "wordlist", "w", "", "File of hostnames, one per line")
	f.StringVarP(&opts.bruteforce, "bruteforce", "b", "", "Prefix wordlist for bruteforce mode (requires -d)")
	f.BoolVar(&opts.passive, "passive", false, "Discover subdomains from certificate transparency logs")
	f.BoolVar(&opts.stdin, "stdin", false, "Read hostnames from stdin")

	f.IntVarP(&opts.concurrent, "concurrent", "c", 50, "Concurrent workers")
	f.IntVar(&opts.timeout, "timeout", 12, "Per-request timeout in seconds")
	f.IntVar(&opts.rate, "rate", 0, "Requests per second (0 = unlimited)")
	f.IntVar(&opts.repeats, "repeats", 2, "Probes that must agree before a finding is confirmed")
	f.StringVar(&opts.proxy, "proxy", "", "Outbound proxy, e.g. http://127.0.0.1:8080")
	f.IntVar(&opts.maxNames, "max", 0, "Cap discovered hostnames (0 = no limit)")

	f.StringVarP(&opts.out, "out", "o", "table", "Output format: "+strings.Join(reporter.Formats(), " | "))
	f.StringVar(&opts.save, "save", "", "Also write the report to this file")
	f.StringVar(&opts.report, "report", "", "Write a standalone HTML report to this file")
	f.BoolVar(&opts.explain, "explain", false, "Print the verification steps behind each finding")
	f.BoolVar(&opts.quiet, "quiet", false, "Suppress progress output")
	f.BoolVar(&opts.onlyFindings, "only-findings", false, "Drop non-findings from written reports")
	f.BoolVar(&opts.noVerify, "no-verify", false, "Report DNS matches without probing (faster, noisier)")
	f.BoolVar(&opts.exitZero, "exit-zero", false, "Always exit 0, even when findings exist")

	f.StringVar(&opts.failOn, "fail-on", "medium", "Minimum confidence to count as a finding: high | medium | low")
	f.BoolVarP(&opts.verbose, "verbose", "v", false, "Show every hostname, not just findings")
	f.BoolVar(&opts.defaultWords, "init-wordlist", false, "Write the built-in prefix list to ./subdomains.txt and exit")
}

// Execute runs the CLI and maps the run outcome onto a process exit code.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		var ec exitError
		if errors.As(err, &ec) {
			os.Exit(ec.code)
		}
		fmt.Fprintf(os.Stderr, "%s error: %v\n", color("✗"), err)
		os.Exit(exitFailed)
	}
}

type exitError struct{ code int }

func (e exitError) Error() string { return fmt.Sprintf("exit status %d", e.code) }

// warnf prints a non-fatal problem to stderr.
func warnf(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "%s %s\n", color("!"), fmt.Sprintf(format, a...))
}

// infof prints progress to stderr, leaving stdout clean for the report.
func infof(format string, a ...any) {
	if opts.quiet {
		return
	}
	fmt.Fprintf(os.Stderr, "%s %s\n", color("*"), fmt.Sprintf(format, a...))
}

func color(sym string) string {
	if os.Getenv("NO_COLOR") != "" || !isTTY() {
		return sym
	}
	return sym
}

func isTTY() bool {
	fi, err := os.Stderr.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

func run(cmd *cobra.Command, _ []string) error {
	if opts.defaultWords {
		const path = "subdomains.txt"
		if err := discovery.DefaultWordlist(path); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "%s wrote %s (%d prefixes) — edit it and pass it with -b\n", color("+"), path, len(discovery.BuiltinPrefixes))
		return nil
	}

	if err := validateFlags(); err != nil {
		return err
	}

	registry, err := services.Load(FingerprintsData)
	if err != nil {
		return fmt.Errorf("loading fingerprint database: %w", err)
	}
	validation.BindRegistry(registry.Detect, registry.DetectIP, matcher.Match, matcher.MatchHeaders)

	started := time.Now()
	targets, mode, notes, err := collectTargets()
	if err != nil {
		return err
	}

	infof("%d targets | %d workers | %ds timeout | %d providers | rate %s",
		len(targets), opts.concurrent, opts.timeout, registry.Count(), rateLabel())

	results, err := scan(targets)
	if err != nil {
		return err
	}

	report := reporter.Build(targetLabel(targets, mode), mode, results, started, time.Since(started))
	report.Notes = append(report.Notes, notes...)
	report.Services = registry.Count()

	if err := emit(report); err != nil {
		return err
	}

	return finish(report)
}

// validateFlags rejects impossible combinations before any network traffic,
// which is far cheaper than failing halfway through a long scan.
func validateFlags() error {
	// Mode-specific requirements first, so the operator is told exactly which
	// flag is missing rather than being told there is nothing to scan.
	if opts.bruteforce != "" && opts.domain == "" {
		return errors.New("-b needs a base domain: takeoverx -b prefixes.txt -d example.com")
	}
	if opts.passive && opts.domain == "" {
		return errors.New("--passive needs a base domain: takeoverx --passive -d example.com")
	}
	if opts.domain == "" && opts.wordlist == "" && !opts.stdin && !opts.passive {
		return errors.New("nothing to scan: pass -d, -w, --passive, or pipe hostnames with --stdin")
	}
	if opts.concurrent < 1 {
		return fmt.Errorf("-c must be at least 1, got %d", opts.concurrent)
	}
	if opts.timeout < 1 {
		return fmt.Errorf("--timeout must be at least 1 second, got %d", opts.timeout)
	}
	if opts.repeats < 1 {
		return fmt.Errorf("--repeats must be at least 1, got %d", opts.repeats)
	}
	format := strings.ToLower(opts.out)
	if !containsString(reporter.Formats(), format) {
		return fmt.Errorf("unknown -o format %q (want one of: %s)", opts.out, strings.Join(reporter.Formats(), ", "))
	}
	switch strings.ToLower(opts.failOn) {
	case "high", "medium", "low":
	default:
		return fmt.Errorf("--fail-on must be high, medium or low, got %q", opts.failOn)
	}
	if opts.proxy != "" {
		if _, err := parseProxyFlag(opts.proxy); err != nil {
			return fmt.Errorf("--proxy: %w", err)
		}
	}
	return nil
}

func rateLabel() string {
	if opts.rate <= 0 {
		return "unlimited"
	}
	return fmt.Sprintf("%d/s", opts.rate)
}

func containsString(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}

func targetLabel(targets []string, mode string) string {
	if opts.domain != "" {
		return opts.domain
	}
	if mode != "" {
		return fmt.Sprintf("%d hostnames", len(targets))
	}
	if len(targets) > 0 {
		return targets[0]
	}
	return "(none)"
}

// collectTargets resolves every input source into one deduplicated list.
func collectTargets() ([]string, string, []string, error) {
	var (
		targets []string
		notes   []string
		modes   []string
	)

	loadOpts := loader.Options{Base: opts.domain, AllowWildcardLines: true}
	var stdinIn io.Reader
	if opts.stdin {
		stdinIn = os.Stdin
	}

	loaded, err := loader.Load(opts.domain, opts.wordlist, stdinIn, loadOpts)
	if err != nil {
		return nil, "", nil, err
	}
	targets = append(targets, loaded.Domains...)
	modes = append(modes, "list")
	if loaded.Duplicate > 0 {
		notes = append(notes, fmt.Sprintf("%d duplicate input(s) collapsed", loaded.Duplicate))
	}
	if len(loaded.Rejected) > 0 {
		notes = append(notes, fmt.Sprintf("%d input line(s) rejected as invalid hostnames", len(loaded.Rejected)))
		for i, r := range loaded.Rejected {
			if i >= 3 {
				break
			}
			notes = append(notes, fmt.Sprintf("rejected %q: %s", r.Input, r.Reason))
		}
	}

	if opts.passive {
		src := &discovery.PassiveSource{
			Client:   httpClientNoTimeout(),
			MaxNames: opts.maxNames,
		}
		ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		names, err := src.Discover(ctx, opts.domain)
		cancel()
		if err != nil {
			// Passive discovery is an accelerator, not a prerequisite: the
			// scan must still run on whatever the caller supplied.
			warnf("passive discovery failed, continuing with explicit targets: %v", err)
			notes = append(notes, "certificate transparency discovery failed")
		} else {
			targets = mergeUnique(targets, names)
			modes = append(modes, "passive")
			infof("certificate transparency returned %d additional hostnames", len(names))
		}
	}

	if opts.bruteforce != "" {
		gen, err := discovery.Generate(opts.domain, opts.bruteforce)
		if err != nil {
			return nil, "", nil, err
		}
		targets = mergeUnique(targets, gen)
		modes = append(modes, "bruteforce")
		infof("bruteforce generated %d candidates", len(gen))
	}

	if opts.maxNames > 0 && len(targets) > opts.maxNames {
		notes = append(notes, fmt.Sprintf("scan capped at --max %d of %d targets", opts.maxNames, len(targets)))
		targets = targets[:opts.maxNames]
	}

	if len(targets) == 0 {
		return nil, "", nil, errors.New("no hostnames left to scan after discovery")
	}
	return targets, strings.Join(modes, "+"), notes, nil
}

func mergeUnique(existing, extra []string) []string {
	seen := make(map[string]struct{}, len(existing)+len(extra))
	out := make([]string, 0, len(existing)+len(extra))
	for _, v := range append(append([]string{}, existing...), extra...) {
		if v == "" {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}

// scan runs the verification pipeline across all targets with a bounded pool.
func scan(targets []string) ([]models.ScanResult, error) {
	client := httpclient.New(time.Duration(opts.timeout)*time.Second, opts.rate, opts.proxy)
	defer client.CloseIdle()

	cfg := validation.DefaultConfig()
	cfg.Repeats = opts.repeats
	cfg.SkipVerify = opts.noVerify

	verifier := validation.New(client, cfg)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sigCh)
	go func() {
		select {
		case <-sigCh:
			warnf("interrupted — finishing in-flight checks and writing what we have")
			cancel()
		case <-ctx.Done():
		}
	}()

	// A wildcard zone makes every hostname resolve, so each zone is probed once
	// and the verdict reused for every host beneath it. The verifier owns the
	// call so that --no-verify skips it entirely.
	wildcards := newWildcardCache(dns.WildcardActive)
	verifier.SetWildcardCheck(wildcards.isWildcard)
	progress := newProgress(len(targets))

	var (
		mu      sync.Mutex
		results = make([]models.ScanResult, 0, len(targets))
		wg      sync.WaitGroup
	)

	sem := make(chan struct{}, opts.concurrent)
	for _, host := range targets {
		select {
		case <-ctx.Done():
			goto done
		case sem <- struct{}{}:
		}

		wg.Add(1)
		go func(host string) {
			defer wg.Done()
			defer func() { <-sem }()

			res := verifier.Verify(ctx, host, validation.DefaultWildcardBase(host))
			appendLocked(&mu, &results, toScanResult(res))
			progress.tick(res)
		}(host)
	}

done:
	wg.Wait()
	dns.ResetCache()

	progress.finish()
	return results, nil
}

// appendLocked keeps result collection race-free without serialising the
// verification work itself.
func appendLocked(mu *sync.Mutex, dst *[]models.ScanResult, v models.ScanResult) {
	mu.Lock()
	*dst = append(*dst, v)
	mu.Unlock()
}

func toScanResult(v validation.Result) models.ScanResult {
	out := models.ScanResult{
		Subdomain:   v.Subdomain,
		Status:      string(v.Status),
		Confidence:  string(v.Confidence),
		Reason:      v.Reason,
		Remediation: v.Remediation,
		DocsURL:     v.DocsURL,
		Severity:    v.Severity,
		MatchedBy:   v.MatchedBy,
		Duration:    v.Duration.Seconds() * 1000,
	}
	if v.Service != nil {
		out.Service = v.Service.Name
		// Verification normally propagates the provider's impact rating, but a
		// registry entry is the authoritative source when it did not.
		if out.Severity == "" {
			out.Severity = v.Service.Severity
		}
	}
	out.Steps = v.Steps.Passed()
	if d := dnsResultFor(v); d != nil {
		out.RecordType = string(d.RecordType)
		out.CNAME = d.CNAME
		out.CNAMEChain = strings.Join(d.CNAMEChain, " -> ")
		out.IPs = d.IPs
	}
	return out
}

// dnsResultFor re-reads the cached DNS answer for reporting. Verification
// already resolved it, so this costs no extra queries.
func dnsResultFor(v validation.Result) *models.DNSResult {
	d := dns.Resolve(v.Subdomain)
	if d == nil || d.RecordType == models.RecordNone {
		return nil
	}
	return d
}

// emit writes the report in the requested formats.
func emit(r *reporter.Report) error {
	format := strings.ToLower(opts.out)

	stdoutView := r
	if !opts.verbose {
		stdoutView = reporter.FindingsOnly(r)
	}
	fileView := stdoutView

	switch format {
	case reporter.FormatHTML:
		// HTML is a document: it only makes sense on a file.
		path := defaultReportPath(opts.report, "report.html")
		if err := reporter.SaveFile(fileView, format, path); err != nil {
			return err
		}
		infof("HTML report written to %s", path)
	default:
		if err := reporter.Write(os.Stdout, stdoutView, format); err != nil {
			return err
		}
	}

	if opts.save != "" {
		saveFormat := format
		if format == reporter.FormatHTML {
			saveFormat = reporter.FormatJSON
		}
		if err := reporter.SaveFile(fileView, saveFormat, opts.save); err != nil {
			return fmt.Errorf("writing %q: %w", opts.save, err)
		}
		infof("report saved to %s", opts.save)
	}
	if opts.report != "" && format != reporter.FormatHTML {
		if err := reporter.SaveFile(fileView, reporter.FormatHTML, opts.report); err != nil {
			return fmt.Errorf("writing %q: %w", opts.report, err)
		}
		infof("HTML report written to %s", opts.report)
	}

	if opts.explain {
		printExplain(r)
	}
	return nil
}

func defaultReportPath(flagValue, fallback string) string {
	if flagValue != "" {
		return flagValue
	}
	return fallback
}

func printExplain(r *reporter.Report) {
	fmt.Fprintln(os.Stderr, "\n── verification detail ──")
	for _, s := range r.Results {
		if len(s.Steps) == 0 {
			continue
		}
		fmt.Fprintf(os.Stderr, "%s [%s/%s]\n", s.Subdomain, s.Status, s.Confidence)
		for _, step := range s.Steps {
			fmt.Fprintf(os.Stderr, "    + %s\n", step)
		}
	}
}

// finish maps the scan outcome onto an exit code for CI use.
func finish(r *reporter.Report) error {
	threshold := strings.ToLower(opts.failOn)
	actionable := 0
	for _, s := range r.Results {
		if !s.Vulnerable() {
			continue
		}
		if confidenceAtLeast(s.Confidence, threshold) {
			actionable++
		}
	}

	if opts.quiet {
		fmt.Fprintf(os.Stdout, "%d/%d actionable findings at %s confidence or above\n",
			actionable, r.Summary.Total, threshold)
	}

	if actionable == 0 {
		infof("no actionable takeover risk found")
		return nil
	}

	warnf("%d actionable finding(s) at %s confidence or above", actionable, threshold)
	if opts.exitZero {
		return nil
	}
	return exitError{code: exitFound}
}

func confidenceAtLeast(got, threshold string) bool {
	rank := map[string]int{"high": 0, "medium": 1, "low": 2}
	g, ok := rank[strings.ToLower(got)]
	if !ok {
		g = 2
	}
	t, ok := rank[threshold]
	if !ok {
		t = 1
	}
	return g <= t
}

func banner() string {
	return `
  ████████╗ █████╗ ██╗  ██╗██╗   ██╗ ██████╗ ██╗   ██╗██████╗ ██╗  ██╗
  ╚══██╔══╝██╔══██╗██║ ██╔╝██║   ██║██╔════╝ ██║   ██║██╔════╝ ██║  ██║
     ██║   ███████║█████╔╝ ██║   ██║██║  ███╗██║   ██║█████╗  ██████╔╝
     ██║   ██╔══██║██╔═██╗ ██║   ██║██║   ██║╚██╗ ██╔╝██╔══╝  ██╔══██╗
     ██║   ██║  ██║██║  ██╗███████║╚██████╔╝ ╚████╔╝ ███████╗██║  ██║██╔╝ ██╗
     ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝ ╚═════╝   ╚═══╝  ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝
`
}
