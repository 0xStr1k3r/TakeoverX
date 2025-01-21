<div align="center">

```
  ████████╗ █████╗ ██╗  ██╗███████╗ ██████╗ ██╗   ██╗███████╗██████╗ ██╗  ██╗
  ╚══██╔══╝██╔══██╗██║ ██╔╝██╔════╝██╔═══██╗██║   ██║██╔════╝██╔══██╗╚██╗██╔╝
     ██║   ███████║█████╔╝ █████╗  ██║   ██║██║   ██║█████╗  ██████╔╝ ╚███╔╝
     ██║   ██╔══██║██╔═██╗ ██╔══╝  ██║   ██║╚██╗ ██╔╝██╔══╝  ██╔══██╗ ██╔██╗
     ██║   ██║  ██║██║  ██╗███████╗╚██████╔╝ ╚████╔╝ ███████╗██║  ██║██╔╝ ██╗
     ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝ ╚═════╝   ╚═══╝  ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝
```

**High-performance subdomain takeover scanner written in Go**

![Go](https://img.shields.io/badge/Go-1.21+-00ADD8?style=flat-square&logo=go)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![Platforms](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS-lightgrey?style=flat-square)

</div>

---

> ⚠️ **Legal Disclaimer**
> TakeoverX is intended for **authorized security testing, bug bounty hunting, and educational purposes only**.
> You must have **explicit written permission** from the asset owner before scanning any domain.
> Unauthorized use against systems you do not own or have permission to test is **illegal** and may result in criminal prosecution.
> The authors take **no responsibility** for misuse of this tool.

---

## Features

- 🎯 **51+ cloud service fingerprints** — AWS S3, GitHub Pages, Heroku, Netlify, Vercel, Azure, Firebase, Cloudflare, Render, and more
- ⚡ **High-performance concurrent scanning** — configurable worker pool (`-c`)
- 🔎 **Three discovery modes** — single domain, wordlist scan, or bruteforce generation
- 🔗 **Multi-level CNAME chain analysis** — detects indirect takeovers across hops
- 🛡️ **False-positive prevention** — retry verification layer confirms fingerprints consistently
- 📡 **Header fingerprinting** — secondary signal via `Server`, `X-Powered-By`, and other headers
- ⏱️ **Rate limiting** — configurable requests-per-second (`--rate`)
- 📊 **Multiple output formats** — table (default), JSON, CSV
- 💾 **Save results** — `-s results.json` saves VULNERABLE findings to a JSON file
- 📄 **Professional HTML report** — dark-theme pentest report with summary cards
- 🛑 **Graceful shutdown** — CTRL+C drains workers cleanly

---

## Installation

### Quick Install (Recommended)

```bash
git clone https://github.com/0xStr1k3r/TakeoverX.git
cd TakeoverX
chmod +x install.sh
./install.sh
```

The installer automatically:
- Detects your OS (Debian/Ubuntu, Arch, RHEL/Fedora, openSUSE, Alpine, macOS)
- Installs Go if not present or too old (minimum Go 1.21)
- Builds the binary with optimizations (`-ldflags="-s -w"`)
- Installs to `/usr/local/bin/takeoverx`

### Manual Build

```bash
git clone https://github.com/0xStr1k3r/TakeoverX.git
cd TakeoverX
go build -ldflags="-s -w" -trimpath -o takeoverx .
sudo mv takeoverx /usr/local/bin/
```

### Requirements

| Requirement | Version  |
|-------------|----------|
| Go          | ≥ 1.21   |
| OS          | Linux / macOS |

---

## Quick Start

```bash
# Scan a single subdomain
takeoverx -d sub.example.com

# Scan a list of subdomains (use your own wordlist or one from SecLists)
takeoverx -w subdomains.txt

# Bruteforce: generate & scan subdomain candidates for a domain
takeoverx -d example.com -b wordlist.txt

# High-throughput scan
takeoverx -d example.com -b wordlist.txt -c 200

# Save vulnerable results to JSON
takeoverx -d example.com -b wordlist.txt -s results.json

# Generate HTML report
takeoverx -w subs.txt --report report.html

# Show ALL results including SAFE/UNKNOWN
takeoverx -w subs.txt -v

# Output as JSON to stdout
takeoverx -w subs.txt -o json

# Skip retry verification (faster, more false positives)
takeoverx -w subs.txt --no-verify
```

---

## CLI Flags

| Flag                | Short | Default       | Description                                      |
|---------------------|-------|---------------|--------------------------------------------------|
| `--wordlist`        | `-w`  | —             | Path to subdomain list (one per line)            |
| `--domain`          | `-d`  | —             | Single subdomain, or base domain for bruteforce  |
| `--bruteforce`      | `-b`  | —             | Bruteforce prefix wordlist (requires `-d`)       |
| `--concurrent`      | `-c`  | `50`          | Number of concurrent workers                     |
| `--out`             | `-o`  | `table`       | Output format: `table` \| `json` \| `csv`        |
| `--save`            | `-s`  | —             | Save VULNERABLE results as JSON to file          |
| `--report`          | —     | —             | Save full HTML report to file                    |
| `--timeout`         | `-t`  | `12`          | HTTP probe timeout in seconds                    |
| `--rate`            | —     | `0` (unlimited) | Max HTTP requests per second                   |
| `--verbose`         | `-v`  | `false`       | Show all results (SAFE + UNKNOWN + VULNERABLE)   |
| `--no-verify`       | —     | `false`       | Skip retry verification (faster, less accurate)  |
| `--version`         | —     | —             | Print version and exit                           |
| `--help`            | `-h`  | —             | Show help                                        |

---

## Wordlists

TakeoverX does **not** bundle a wordlist — bring your own or use one from [SecLists](https://github.com/danielmiessler/SecLists):

```bash
# Install SecLists (Debian/Ubuntu)
sudo apt install seclists

# Use a SecLists DNS wordlist
takeoverx -d example.com -b /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt

# Or use a small custom wordlist
takeoverx -d example.com -b ~/my-wordlist.txt
```

---

## Discovery Modes

### 1. Recon Mode
Scan a pre-built list of subdomains — ideal when you already have output from tools like [Subfinder](https://github.com/projectdiscovery/subfinder), [Amass](https://github.com/owasp-amass/amass), or [assetfinder](https://github.com/tomnomnom/assetfinder).

```bash
subfinder -d example.com -silent | tee subs.txt
takeoverx -w subs.txt -c 100 --report report.html
```

### 2. Bruteforce Mode
Generate subdomain candidates by prepending a wordlist to a base domain, then scan them all.

```bash
takeoverx -d example.com -b /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
```

Generates: `www.example.com`, `mail.example.com`, `api.example.com`, ...

### 3. Single Domain
Quick check of one subdomain.

```bash
takeoverx -d cdn.example.com
```

---

## Detection Pipeline

```
  Input (wordlist / -d / bruteforce)
              │
              ▼
     DNS Resolver Pool
    (CNAME chain analysis)
              │
              ▼
   Cloud Provider Detector
   (CNAME + chain matching)
              │
              ▼
      HTTP Probe Pool
   (HTTPS → HTTP fallback)
              │
              ▼
   Fingerprint Matcher
   (body + header signals)
              │
              ▼
   Validation Engine
   (retry confirmation ×2)
              │
              ▼
   Result Aggregator
   (table / JSON / CSV / HTML)
```

1. **DNS resolution** — Resolves full CNAME chain (up to 10 hops). Detects NXDOMAIN.
2. **Service detection** — Matches any link in the CNAME chain against 51 service patterns.
3. **HTTP probe** — Sends HTTPS (with HTTP fallback) and captures status, body, headers.
4. **Fingerprint matching** — Checks response body and key headers against known error signatures.
5. **Validation** — Retries the probe 2× to confirm the fingerprint is consistent. Skip with `--no-verify`.

---

## Output

### Default (table)
```
SUBDOMAIN              SERVICE   STATUS       CNAME                              REASON
dev.example.com        AWS S3    VULNERABLE   dev.example.com.s3.amazonaws.com   Fingerprint matched (body)
api.example.com        AWS S3    VULNERABLE   api-bucket.s3.amazonaws.com        Fingerprint matched (body)
```

### JSON (`-o json`)
```json
[
  {
    "subdomain": "dev.example.com",
    "cname": "dev.example.com.s3.amazonaws.com",
    "cname_chain": "dev.example.com.s3.amazonaws.com → s3-w.us-east-1.amazonaws.com",
    "service": "AWS S3",
    "status": "VULNERABLE",
    "reason": "Fingerprint matched (body)"
  }
]
```

### Save to file (`-s results.json`)
Saves only VULNERABLE results as JSON — useful for reporting or piping into other tools.

### HTML Report (`--report report.html`)
Generates a dark-theme pentest report with summary cards, full results table, and color-coded status badges.

---

## Integrate with Recon Pipelines

```bash
# Subfinder → takeoverx → save vulnerable
subfinder -d example.com -silent | tee subs.txt
takeoverx -w subs.txt -s vulns.json 2>/dev/null

# Pipe JSON output through jq
takeoverx -w subs.txt -o json 2>/dev/null | jq '.[].subdomain'

# CI/CD: exit non-zero if any vulnerabilities found
takeoverx -w subs.txt -o json 2>/dev/null | python3 -c "
import sys, json; data = json.load(sys.stdin)
sys.exit(1 if data else 0)
"
```

---

## Supported Services (51)

| Category      | Services                                                                 |
|---------------|--------------------------------------------------------------------------|
| AWS           | S3, CloudFront, Elastic Beanstalk                                        |
| Microsoft     | Azure Web Apps, Azure Storage, Azure CDN                                 |
| Google        | Firebase Hosting, Google Cloud Storage                                   |
| Code Hosting  | GitHub Pages, GitLab Pages, Bitbucket                                    |
| PaaS          | Heroku, Render, Railway, Fly.io                                          |
| CDN / Edge    | Fastly, Cloudflare Pages                                                 |
| CMS / Blog    | WordPress, Ghost, Tumblr, Squarespace, Cargo, Strikingly                 |
| E-commerce    | Shopify, Bigcartel                                                       |
| Marketing     | Netlify, Vercel, Unbounce, Instapage, Campaign Monitor, Wishpond         |
| Support       | Zendesk, Freshdesk, Intercom, Helpscout, Helpjuice, Desk.com, Teamwork   |
| Dev Tools     | Readme.io, JetBrains YouTrack, UserVoice, Canny                          |
| Monitoring    | Statuspage, Pingdom                                                      |
| Other         | Surge, Pantheon, Acquia, Aftership, Anima, Brightcove, Simplebooklet, Agile CRM |

---

## Project Structure

```
TakeoverX/
├── main.go                         # Entry point (embeds fingerprints.json)
├── cmd/
│   └── root.go                     # CLI flags, pipeline orchestration
├── internal/
│   ├── models/models.go            # Core data types
│   ├── loader/loader.go            # Wordlist loader + dedup
│   ├── discovery/bruteforce.go     # Subdomain generator for bruteforce mode
│   ├── dns/resolver.go             # CNAME chain resolver with caching
│   ├── services/detector.go        # Cloud provider fingerprint matching
│   ├── httpclient/probe.go         # HTTP probe + rate limiter
│   ├── matcher/matcher.go          # Body + header fingerprint matching
│   ├── validation/verifier.go      # Retry verification (false-positive prevention)
│   └── reporter/reporter.go        # table / JSON / CSV / HTML output
├── fingerprints/
│   └── services.json               # 51-service fingerprint database (embedded in binary)
├── install.sh                      # Cross-platform installer
└── LICENSE
```

---

## License

This project is licensed under the [MIT License](LICENSE).

---

*Use only on systems and domains you own or have **explicit written authorization** to test.*

