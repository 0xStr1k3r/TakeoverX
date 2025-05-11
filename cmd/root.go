package cmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
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

const version = "1.1.0"

// FingerprintsData is injected from main.go via the embed directive.
var FingerprintsData []byte

var (
	flagWordlist   string
	flagDomain     string
	flagBruteforce string
	flagConcurrent int
	flagOut        string
	flagReport     string
	flagSave       string
	flagVerbose    bool
	flagTimeout    int
	flagRate       int
	flagNoVerify   bool
)

var rootCmd = &cobra.Command{
	Use:     "github.com/0xStr1k3r/TakeoverX",
	Short:   "TakeoverX — High-performance subdomain takeover scanner",
	Long:    banner(),
	Version: version,
	RunE:    run,
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func init() {
	rootCmd.Flags().StringVarP(&flagWordlist, "wordlist", "w", "", "Wordlist of subdomains to scan (one per line)")
	rootCmd.Flags().StringVarP(&flagDomain, "domain", "d", "", "Single domain/subdomain to scan, or base domain for bruteforce")
	rootCmd.Flags().StringVarP(&flagBruteforce, "bruteforce", "b", "", "Bruteforce mode: path to prefix wordlist (requires -d)")
	rootCmd.Flags().IntVarP(&flagConcurrent, "concurrent", "c", 50, "Number of concurrent workers")
	rootCmd.Flags().StringVarP(&flagOut, "out", "o", "table", "Output format: json | table | csv")
	rootCmd.Flags().StringVar(&flagReport, "report", "", "Save HTML report to file (e.g. --report report.html)")
	rootCmd.Flags().StringVarP(&flagSave, "save", "s", "", "Save scan results as JSON to file (e.g. -s results.json)")
	rootCmd.Flags().BoolVarP(&flagVerbose, "verbose", "v", false, "Show all results including SAFE/UNKNOWN (default: VULNERABLE only)")
	rootCmd.Flags().IntVarP(&flagTimeout, "timeout", "t", 12, "HTTP probe timeout in seconds")
	rootCmd.Flags().IntVar(&flagRate, "rate", 0, "Max HTTP requests per second (0 = unlimited)")
	rootCmd.Flags().BoolVar(&flagNoVerify, "no-verify", false, "Skip retry verification (faster but more false positives)")
}

func run(_ *cobra.Command, _ []string) error {
	printBanner()

	if flagWordlist == "" && flagDomain == "" && flagBruteforce == "" {
		return fmt.Errorf("provide -d <domain>, -w <wordlist>, or -d <domain> -b <wordlist>")
	}

	// Clamp concurrency
	if flagConcurrent < 1 {
		flagConcurrent = 1
	}
	if flagConcurrent > 2000 {
		flagConcurrent = 2000
	}

	// Apply HTTP settings
	httpclient.SetTimeout(time.Duration(flagTimeout) * time.Second)
	httpclient.SetRateLimit(flagRate)

	// Load fingerprints
	fps, err := services.LoadFingerprints(FingerprintsData)
	if err != nil {
		return fmt.Errorf("failed to load fingerprints: %w", err)
	}

	// Build domain list
	var domains []string

	switch {
	case flagBruteforce != "":
		if flagDomain == "" {
			return fmt.Errorf("bruteforce mode (-b) requires a base domain (-d)")
		}
		domains, err = discovery.Generate(flagDomain, flagBruteforce)
		if err != nil {
			return fmt.Errorf("bruteforce: %w", err)
		}
		fmt.Fprintf(os.Stderr, "[*] Bruteforce mode: generated %d candidates for %s\n", len(domains), flagDomain)

	default:
		domains, err = loader.LoadDomains(flagWordlist, flagDomain)
		if err != nil {
			return fmt.Errorf("failed to load domains: %w", err)
		}
	}

	if len(domains) == 0 {
		return fmt.Errorf("no valid domains found")
	}

	rateStr := "unlimited"
	if flagRate > 0 {
		rateStr = fmt.Sprintf("%d/s", flagRate)
	}
	fmt.Fprintf(os.Stderr, "[*] Targets: %d | Concurrent: %d | Timeout: %ds | Rate: %s | Fingerprints: %d\n\n",
		len(domains), flagConcurrent, flagTimeout, rateStr, len(fps))

	results := scan(domains, fps)

	// By default output only VULNERABLE; use -v to see all results
	output := make([]models.ScanResult, 0)
	if flagVerbose {
		output = results
	} else {
		for _, r := range results {
			if r.Status == "VULNERABLE" {
				output = append(output, r)
			}
		}
	}

	// Print to stdout
	switch strings.ToLower(flagOut) {
	case "table":
		reporter.PrintTable(output)
	case "csv":
		reporter.PrintCSV(output)
	default:
		reporter.PrintJSON(output)
	}

	// Save JSON to file if -s provided (always vulnerable-only)
	if flagSave != "" {
		vulnOnly := make([]models.ScanResult, 0)
		for _, r := range results {
			if r.Status == "VULNERABLE" {
				vulnOnly = append(vulnOnly, r)
			}
		}
		if err := reporter.SaveJSON(vulnOnly, flagSave); err != nil {
			fmt.Fprintf(os.Stderr, "[!] Failed to save results: %v\n", err)
		} else {
			fmt.Fprintf(os.Stderr, "\n[+] Results saved → %s\n", flagSave)
		}
	}

	// Optional HTML report
	if flagReport != "" {
		if err := reporter.WriteHTML(results, flagReport); err != nil {
			fmt.Fprintf(os.Stderr, "[!] Failed to write report: %v\n", err)
		} else {
			fmt.Fprintf(os.Stderr, "\n[+] HTML report saved → %s\n", flagReport)
		}
	}

	// Summary
	var vulnCount int
	for _, r := range results {
		if r.Status == "VULNERABLE" {
			vulnCount++
		}
	}
	fmt.Fprintf(os.Stderr, "\n[*] Scan complete — %d/%d vulnerable\n", vulnCount, len(domains))

	return nil
}

// scan orchestrates the full detection pipeline using a concurrent worker pool.
func scan(domains []string, fps []models.ServiceFingerprint) []models.ScanResult {
	total := len(domains)
	jobs := make(chan string, total)
	resultsCh := make(chan models.ScanResult, total)

	var (
		wg      sync.WaitGroup
		counter atomic.Int64
	)

	// Graceful cancellation on SIGINT/SIGTERM
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		select {
		case <-sigCh:
			fmt.Fprintf(os.Stderr, "\n[!] Interrupted — stopping workers...\n")
			cancel()
		case <-ctx.Done():
		}
		signal.Stop(sigCh)
	}()

	// Spawn workers
	for i := 0; i < flagConcurrent; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for domain := range jobs {
				select {
				case <-ctx.Done():
					// Drain remaining jobs without processing them
					for range jobs {
					}
					return
				default:
				}
				r := processDomain(domain, fps)
				resultsCh <- r

				done := int(counter.Add(1))
				printProgress(r, done, total)
			}
		}()
	}

	// Feed jobs
	for _, d := range domains {
		jobs <- d
	}
	close(jobs)

	go func() {
		wg.Wait()
		close(resultsCh)
	}()

	var results []models.ScanResult
	for r := range resultsCh {
		results = append(results, r)
	}

	fmt.Fprintln(os.Stderr) // newline after progress bar
	return results
}

// processDomain runs the full 5-step detection pipeline for a single domain.
func processDomain(domain string, fps []models.ServiceFingerprint) models.ScanResult {
	result := models.ScanResult{
		Subdomain: domain,
		Service:   "Unknown",
		Status:    "UNKNOWN",
	}

	// Step 1 — DNS resolution with CNAME chain analysis
	dnsResult := dns.Resolve(domain)
	result.CNAME = dnsResult.CNAME
	if len(dnsResult.CNAMEChain) > 1 {
		result.CNAMEChain = strings.Join(dnsResult.CNAMEChain, " → ")
	}

	// Step 2 — Service detection (checks full CNAME chain + domain itself)
	var matchedFP *models.ServiceFingerprint
	matchedFP = services.Detect(dnsResult.CNAME, dnsResult.CNAMEChain, fps)
	if matchedFP == nil {
		matchedFP = services.Detect(domain, nil, fps)
	}

	// Step 3 — NXDOMAIN handling
	if dnsResult.NXDomain {
		if matchedFP != nil && matchedFP.NXDomain {
			result.Service = matchedFP.Name
			result.Status = "VULNERABLE"
			result.Reason = "NXDOMAIN + CNAME matches " + matchedFP.Name
			return result
		}
		result.Status = "UNKNOWN"
		result.Reason = "NXDOMAIN — domain does not resolve"
		return result
	}

	if matchedFP == nil {
		result.Status = "SAFE"
		result.Reason = "No matching cloud service CNAME"
		return result
	}

	result.Service = matchedFP.Name

	// Step 4 — HTTP probe
	httpResult := httpclient.Probe(domain)
	if httpResult.Error != nil && httpResult.StatusCode == 0 {
		if dnsResult.IsDead && matchedFP.NXDomain {
			result.Status = "VULNERABLE"
			result.Reason = "CNAME target is dead (NXDOMAIN)"
		} else {
			result.Status = "UNKNOWN"
			result.Reason = "HTTP probe failed: " + httpResult.Error.Error()
		}
		return result
	}

	// Step 5 — Fingerprint + header matching
	bodyMatch := matcher.Match(matchedFP, httpResult.Body)
	headerMatch := matcher.MatchHeaders(matchedFP, httpResult.Headers)

	if bodyMatch || headerMatch {
		matchKind := "body"
		if headerMatch && !bodyMatch {
			matchKind = "header"
		}

		// Validation layer: retry to eliminate false positives
		if !flagNoVerify && !validation.Verify(domain, matchedFP) {
			result.Status = "SAFE"
			result.Reason = fmt.Sprintf("HTTP %d — fingerprint matched once but failed retry verification", httpResult.StatusCode)
			return result
		}

		result.Status = "VULNERABLE"
		result.Reason = fmt.Sprintf("Fingerprint matched (%s)", matchKind)
		return result
	}

	result.Status = "SAFE"
	result.Reason = fmt.Sprintf("HTTP %d — fingerprint not matched", httpResult.StatusCode)
	return result
}

// printProgress writes live scan progress to stderr.
func printProgress(r models.ScanResult, done, total int) {
	switch r.Status {
	case "VULNERABLE":
		fmt.Fprintf(os.Stderr, "\r\033[K  \033[31m[VULN]\033[0m %-45s → %-22s (%s)\n",
			r.Subdomain, r.Service, r.Reason)
	default:
		if flagVerbose {
			color := "\033[32m"
			if r.Status == "UNKNOWN" {
				color = "\033[33m"
			}
			fmt.Fprintf(os.Stderr, "\r\033[K  %s[%s]\033[0m %-45s → %s\n",
				color, r.Status, r.Subdomain, r.Service)
		}
	}
	pct := done * 100 / total
	fmt.Fprintf(os.Stderr, "\r  Progress: %d/%d (%d%%)", done, total, pct)
}

func banner() string {
	return `
  ████████╗ █████╗ ██╗  ██╗███████╗ ██████╗ ██╗   ██╗███████╗██████╗ ██╗  ██╗
  ╚══██╔══╝██╔══██╗██║ ██╔╝██╔════╝██╔═══██╗██║   ██║██╔════╝██╔══██╗╚██╗██╔╝
     ██║   ███████║█████╔╝ █████╗  ██║   ██║██║   ██║█████╗  ██████╔╝ ╚███╔╝
     ██║   ██╔══██║██╔═██╗ ██╔══╝  ██║   ██║╚██╗ ██╔╝██╔══╝  ██╔══██╗ ██╔██╗
     ██║   ██║  ██║██║  ██╗███████╗╚██████╔╝ ╚████╔╝ ███████╗██║  ██║██╔╝ ██╗
     ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝ ╚═════╝   ╚═══╝  ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝

  Subdomain Takeover Scanner  |  51 cloud providers  |  Bug Bounty Ready
  Version: v` + version + `
`
}

func printBanner() {
	fmt.Fprintln(os.Stderr, banner())
}


