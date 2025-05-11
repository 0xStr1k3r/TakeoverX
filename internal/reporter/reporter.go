package reporter

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"html/template"
	"os"
	"text/tabwriter"
	"time"

	"github.com/0xStr1k3r/TakeoverX/internal/models"
)

const htmlTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>TakeoverX — Subdomain Takeover Report</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap');

  :root {
    --bg-primary: #060910;
    --bg-secondary: #0d1117;
    --bg-card: #111827;
    --bg-hover: #1a2233;
    --border: #1e2d3d;
    --border-bright: #2d4a6e;
    --text-primary: #e2e8f0;
    --text-secondary: #94a3b8;
    --text-muted: #4a5568;
    --accent-blue: #3b82f6;
    --accent-blue-glow: rgba(59,130,246,0.15);
    --accent-red: #ef4444;
    --accent-red-glow: rgba(239,68,68,0.12);
    --accent-green: #10b981;
    --accent-green-glow: rgba(16,185,129,0.12);
    --accent-yellow: #f59e0b;
    --accent-yellow-glow: rgba(245,158,11,0.12);
    --accent-purple: #8b5cf6;
    --radius: 10px;
    --radius-sm: 6px;
  }

  * { box-sizing: border-box; margin: 0; padding: 0; }

  body {
    font-family: 'Inter', 'Segoe UI', sans-serif;
    background: var(--bg-primary);
    color: var(--text-primary);
    min-height: 100vh;
    line-height: 1.6;
  }

  /* ── BACKGROUND GRID ── */
  body::before {
    content: '';
    position: fixed;
    inset: 0;
    background-image:
      linear-gradient(rgba(59,130,246,0.03) 1px, transparent 1px),
      linear-gradient(90deg, rgba(59,130,246,0.03) 1px, transparent 1px);
    background-size: 40px 40px;
    pointer-events: none;
    z-index: 0;
  }

  /* ── HEADER ── */
  header {
    position: relative;
    z-index: 10;
    background: linear-gradient(180deg, #0a1628 0%, #0d1117 100%);
    border-bottom: 1px solid var(--border);
    padding: 0 40px;
    display: flex;
    align-items: center;
    justify-content: space-between;
    min-height: 72px;
    gap: 16px;
  }

  header::after {
    content: '';
    position: absolute;
    bottom: 0; left: 0; right: 0;
    height: 1px;
    background: linear-gradient(90deg, transparent, var(--accent-blue), transparent);
    opacity: 0.4;
  }

  .header-left {
    display: flex;
    align-items: center;
    gap: 14px;
  }

  .logo-icon {
    width: 38px; height: 38px;
    background: linear-gradient(135deg, var(--accent-blue), var(--accent-purple));
    border-radius: 9px;
    display: flex; align-items: center; justify-content: center;
    font-size: 18px;
    flex-shrink: 0;
    box-shadow: 0 0 20px rgba(59,130,246,0.3);
  }

  .header-title h1 {
    font-size: 1.2rem;
    font-weight: 700;
    color: var(--text-primary);
    letter-spacing: 0.3px;
  }

  .header-title p {
    color: var(--text-muted);
    font-size: 0.75rem;
    margin-top: 1px;
    font-family: 'JetBrains Mono', monospace;
  }

  .header-right {
    display: flex;
    align-items: center;
    gap: 20px;
  }

  .author-tag {
    display: flex;
    align-items: center;
    gap: 8px;
    background: linear-gradient(135deg, rgba(59,130,246,0.1), rgba(139,92,246,0.1));
    border: 1px solid rgba(59,130,246,0.25);
    border-radius: 50px;
    padding: 6px 14px;
    font-size: 0.8rem;
    font-weight: 600;
    color: var(--accent-blue);
    letter-spacing: 0.5px;
    font-family: 'JetBrains Mono', monospace;
  }

  .author-tag::before {
    content: '⚡';
    font-size: 13px;
  }

  /* ── SUMMARY ── */
  .summary {
    position: relative;
    z-index: 1;
    display: flex;
    gap: 16px;
    padding: 28px 40px 20px;
    flex-wrap: wrap;
  }

  .card {
    flex: 1;
    min-width: 150px;
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    padding: 20px 24px;
    position: relative;
    overflow: hidden;
    transition: transform 0.2s, border-color 0.2s;
  }

  .card:hover { transform: translateY(-2px); }

  .card::before {
    content: '';
    position: absolute;
    top: 0; left: 0; right: 0;
    height: 2px;
    border-radius: var(--radius) var(--radius) 0 0;
  }

  .card-total::before   { background: linear-gradient(90deg, var(--accent-blue), var(--accent-purple)); }
  .card-vuln::before    { background: linear-gradient(90deg, var(--accent-red), #dc2626); }
  .card-safe::before    { background: linear-gradient(90deg, var(--accent-green), #059669); }
  .card-unknown::before { background: linear-gradient(90deg, var(--accent-yellow), #d97706); }

  .card:hover { border-color: var(--border-bright); }

  .card-icon {
    font-size: 22px;
    margin-bottom: 10px;
    display: block;
  }

  .card .num {
    font-size: 2.4rem;
    font-weight: 700;
    line-height: 1;
    font-variant-numeric: tabular-nums;
  }

  .card .label {
    color: var(--text-secondary);
    font-size: 0.72rem;
    text-transform: uppercase;
    letter-spacing: 1px;
    margin-top: 6px;
    font-weight: 500;
  }

  .card-total   .num { color: var(--accent-blue); }
  .card-vuln    .num { color: var(--accent-red); }
  .card-safe    .num { color: var(--accent-green); }
  .card-unknown .num { color: var(--accent-yellow); }

  /* ── SECTION ── */
  .container {
    position: relative;
    z-index: 1;
    padding: 8px 40px 60px;
  }

  .section-header {
    display: flex;
    align-items: center;
    gap: 10px;
    margin-bottom: 16px;
  }

  .section-header h2 {
    font-size: 1rem;
    font-weight: 600;
    color: var(--text-primary);
  }

  .section-header .count-pill {
    background: var(--accent-red-glow);
    border: 1px solid rgba(239,68,68,0.3);
    color: var(--accent-red);
    font-size: 0.72rem;
    font-weight: 600;
    padding: 2px 9px;
    border-radius: 20px;
    font-family: 'JetBrains Mono', monospace;
  }

  .empty-state {
    text-align: center;
    padding: 64px 20px;
    color: var(--text-muted);
  }

  .empty-state .icon { font-size: 48px; margin-bottom: 16px; display: block; }
  .empty-state h3 { font-size: 1.1rem; color: var(--text-secondary); margin-bottom: 8px; }
  .empty-state p  { font-size: 0.875rem; }

  /* ── FINDINGS TABLE ── */
  .findings-table {
    width: 100%;
    border-collapse: collapse;
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    overflow: hidden;
  }

  .findings-table thead th {
    background: #0d1520;
    color: var(--text-muted);
    font-size: 0.68rem;
    text-transform: uppercase;
    letter-spacing: 1.2px;
    font-weight: 600;
    padding: 12px 16px;
    text-align: left;
    border-bottom: 1px solid var(--border);
    white-space: nowrap;
  }

  .findings-table thead th:first-child { width: 40px; text-align: center; }

  /* ── MAIN ROW ── */
  .main-row {
    cursor: pointer;
    transition: background 0.15s;
    border-bottom: 1px solid var(--border);
  }

  .main-row:last-of-type { border-bottom: none; }

  .main-row:hover td { background: var(--bg-hover); }

  .main-row.open td { background: var(--bg-hover); border-bottom: none; }

  .main-row td {
    padding: 14px 16px;
    font-size: 0.875rem;
    vertical-align: middle;
    transition: background 0.15s;
  }

  .toggle-cell {
    text-align: center;
    width: 40px;
  }

  .toggle-btn {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 24px; height: 24px;
    border-radius: 6px;
    background: rgba(59,130,246,0.08);
    border: 1px solid rgba(59,130,246,0.2);
    color: var(--accent-blue);
    font-size: 11px;
    transition: all 0.2s;
    user-select: none;
  }

  .main-row.open .toggle-btn {
    background: rgba(59,130,246,0.18);
    border-color: rgba(59,130,246,0.4);
    transform: rotate(90deg);
  }

  .subdomain-cell {
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.82rem;
    color: var(--text-primary);
    font-weight: 500;
  }

  .subdomain-cell .sub-link {
    color: var(--accent-blue);
    text-decoration: none;
  }

  .subdomain-cell .sub-link:hover { text-decoration: underline; }

  .cname-cell {
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.78rem;
    color: var(--text-secondary);
    max-width: 220px;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .service-pill {
    display: inline-flex;
    align-items: center;
    gap: 5px;
    background: rgba(139,92,246,0.1);
    border: 1px solid rgba(139,92,246,0.25);
    color: #a78bfa;
    font-size: 0.72rem;
    font-weight: 600;
    padding: 3px 10px;
    border-radius: 20px;
    white-space: nowrap;
  }

  .badge {
    display: inline-flex;
    align-items: center;
    gap: 5px;
    padding: 4px 11px;
    border-radius: 20px;
    font-size: 0.72rem;
    font-weight: 700;
    letter-spacing: 0.5px;
    white-space: nowrap;
  }

  .badge-VULNERABLE {
    background: var(--accent-red-glow);
    border: 1px solid rgba(239,68,68,0.35);
    color: var(--accent-red);
  }

  .badge-VULNERABLE::before { content: '●'; font-size: 7px; }

  .badge-SAFE {
    background: var(--accent-green-glow);
    border: 1px solid rgba(16,185,129,0.35);
    color: var(--accent-green);
  }

  .badge-UNKNOWN {
    background: var(--accent-yellow-glow);
    border: 1px solid rgba(245,158,11,0.35);
    color: var(--accent-yellow);
  }

  .reason-cell {
    font-size: 0.8rem;
    color: var(--text-secondary);
    max-width: 260px;
  }

  /* ── EXPAND ROW ── */
  .expand-row { display: none; }
  .expand-row.visible { display: table-row; }

  .expand-row td {
    padding: 0;
    border-bottom: 1px solid var(--border);
    background: #0a1020;
  }

  .expand-content {
    padding: 20px 24px 24px 56px;
    animation: slideDown 0.2s ease;
  }

  @keyframes slideDown {
    from { opacity: 0; transform: translateY(-6px); }
    to   { opacity: 1; transform: translateY(0); }
  }

  .expand-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
    gap: 14px;
    margin-bottom: 16px;
  }

  .detail-card {
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: var(--radius-sm);
    padding: 14px 16px;
  }

  .detail-card .dc-label {
    font-size: 0.65rem;
    text-transform: uppercase;
    letter-spacing: 1.2px;
    color: var(--text-muted);
    font-weight: 600;
    margin-bottom: 6px;
  }

  .detail-card .dc-value {
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.8rem;
    color: var(--text-primary);
    word-break: break-all;
    line-height: 1.5;
  }

  .cname-chain {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 6px;
  }

  .chain-hop {
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.75rem;
    background: rgba(59,130,246,0.08);
    border: 1px solid rgba(59,130,246,0.15);
    color: var(--text-secondary);
    padding: 3px 9px;
    border-radius: 4px;
  }

  .chain-arrow {
    color: var(--text-muted);
    font-size: 0.75rem;
  }

  .severity-bar {
    height: 4px;
    border-radius: 2px;
    background: linear-gradient(90deg, var(--accent-red), #dc2626);
    margin-top: 10px;
    box-shadow: 0 0 8px rgba(239,68,68,0.4);
  }

  /* ── FOOTER ── */
  footer {
    position: relative;
    z-index: 1;
    text-align: center;
    color: var(--text-muted);
    padding: 28px 20px;
    font-size: 0.78rem;
    border-top: 1px solid var(--border);
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 8px;
  }

  footer a { color: var(--accent-blue); text-decoration: none; }
  footer a:hover { text-decoration: underline; }

  /* ── SCROLLBAR ── */
  ::-webkit-scrollbar { width: 6px; height: 6px; }
  ::-webkit-scrollbar-track { background: var(--bg-primary); }
  ::-webkit-scrollbar-thumb { background: var(--border-bright); border-radius: 3px; }

  /* ── RESPONSIVE ── */
  @media (max-width: 768px) {
    header, .summary, .container { padding-left: 16px; padding-right: 16px; }
    .header-title p { display: none; }
    .findings-table .reason-cell, .findings-table .cname-cell { display: none; }
    .expand-content { padding-left: 20px; }
  }
</style>
</head>
<body>

<header>
  <div class="header-left">
    <div class="logo-icon">🎯</div>
    <div class="header-title">
      <h1>TakeoverX — Subdomain Takeover Report</h1>
      <p>Generated: {{.GeneratedAt}} &nbsp;·&nbsp; {{.Total}} domains scanned</p>
    </div>
  </div>
  <div class="header-right">
    <div class="author-tag">0xStr1k3r</div>
  </div>
</header>

<div class="summary">
  <div class="card card-total">
    <span class="card-icon">🔍</span>
    <div class="num">{{.Total}}</div>
    <div class="label">Total Scanned</div>
  </div>
  <div class="card card-vuln">
    <span class="card-icon">🚨</span>
    <div class="num">{{.Vulnerable}}</div>
    <div class="label">Vulnerable</div>
  </div>
  <div class="card card-safe">
    <span class="card-icon">✅</span>
    <div class="num">{{.Safe}}</div>
    <div class="label">Safe</div>
  </div>
  <div class="card card-unknown">
    <span class="card-icon">❓</span>
    <div class="num">{{.Unknown}}</div>
    <div class="label">Unknown</div>
  </div>
</div>

<div class="container">
  <div class="section-header">
    <h2>🔥 Findings</h2>
    <span class="count-pill">{{.Vulnerable}} VULNERABLE</span>
  </div>

  {{if eq .Vulnerable 0}}
  <div class="empty-state">
    <span class="icon">🛡️</span>
    <h3>No vulnerable subdomains found</h3>
    <p>All scanned domains appear to be safe. Run with <code>-v</code> to include all results.</p>
  </div>
  {{else}}
  <table class="findings-table">
    <thead>
      <tr>
        <th></th>
        <th>#</th>
        <th>Subdomain</th>
        <th>CNAME</th>
        <th>Service</th>
        <th>Status</th>
        <th>Reason</th>
      </tr>
    </thead>
    <tbody>
    {{range $i, $r := .Results}}{{if eq $r.Status "VULNERABLE"}}
      <tr class="main-row" onclick="toggle(this)" data-idx="{{$i}}">
        <td class="toggle-cell"><span class="toggle-btn">▶</span></td>
        <td style="color:var(--text-muted);font-size:0.78rem;font-family:'JetBrains Mono',monospace;">{{add $i 1}}</td>
        <td class="subdomain-cell">
          <a class="sub-link" href="https://{{$r.Subdomain}}" target="_blank" rel="noopener" onclick="event.stopPropagation()">{{$r.Subdomain}}</a>
        </td>
        <td class="cname-cell" title="{{$r.CNAME}}">{{$r.CNAME}}</td>
        <td><span class="service-pill">{{$r.Service}}</span></td>
        <td><span class="badge badge-{{$r.Status}}">{{$r.Status}}</span></td>
        <td class="reason-cell">{{$r.Reason}}</td>
      </tr>
      <tr class="expand-row" id="exp-{{$i}}">
        <td colspan="7">
          <div class="expand-content">
            <div class="expand-grid">
              <div class="detail-card">
                <div class="dc-label">🌐 Full Subdomain</div>
                <div class="dc-value">{{$r.Subdomain}}</div>
                <div class="severity-bar"></div>
              </div>
              <div class="detail-card">
                <div class="dc-label">🔗 Primary CNAME Target</div>
                <div class="dc-value">{{if $r.CNAME}}{{$r.CNAME}}{{else}}<span style="color:var(--text-muted)">—</span>{{end}}</div>
              </div>
              <div class="detail-card">
                <div class="dc-label">☁️ Cloud Service</div>
                <div class="dc-value">{{if $r.Service}}{{$r.Service}}{{else}}<span style="color:var(--text-muted)">Unknown</span>{{end}}</div>
              </div>
              <div class="detail-card">
                <div class="dc-label">📋 Detection Reason</div>
                <div class="dc-value">{{if $r.Reason}}{{$r.Reason}}{{else}}<span style="color:var(--text-muted)">—</span>{{end}}</div>
              </div>
              {{if $r.CNAMEChain}}
              <div class="detail-card" style="grid-column: 1 / -1;">
                <div class="dc-label">🔄 Full CNAME Chain</div>
                <div class="dc-value">
                  <div class="cname-chain">
                    {{$r.Subdomain}}
                    <span class="chain-arrow">→</span>
                    <span class="chain-hop">{{$r.CNAMEChain}}</span>
                  </div>
                </div>
              </div>
              {{end}}
            </div>
          </div>
        </td>
      </tr>
    {{end}}{{end}}
    </tbody>
  </table>
  {{end}}
</div>

<footer>
  <span>🎯 TakeoverX</span>
  <span style="color:var(--border-bright)">·</span>
  <span>Bug Bounty Ready Subdomain Takeover Scanner</span>
  <span style="color:var(--border-bright)">·</span>
  <span>by <strong style="color:var(--accent-blue)">0xStr1k3r</strong></span>
</footer>

<script>
  function toggle(row) {
    var idx = row.dataset.idx;
    var expRow = document.getElementById('exp-' + idx);
    var isOpen = row.classList.contains('open');
    row.classList.toggle('open', !isOpen);
    expRow.classList.toggle('visible', !isOpen);
  }
</script>
</body>
</html>`

type reportData struct {
	GeneratedAt string
	Total       int
	Vulnerable  int
	Safe        int
	Unknown     int
	Results     []models.ScanResult
}

// PrintJSON outputs results as indented JSON to stdout.
func PrintJSON(results []models.ScanResult) {
	if results == nil {
		results = []models.ScanResult{}
	}
	data, _ := json.MarshalIndent(results, "", "  ")
	fmt.Println(string(data))
}

// PrintTable outputs results as an aligned table to stdout.
func PrintTable(results []models.ScanResult) {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
	fmt.Fprintln(w, "SUBDOMAIN\tSERVICE\tSTATUS\tCNAME\tREASON")
	fmt.Fprintln(w, "---------\t-------\t------\t-----\t------")
	for _, r := range results {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", r.Subdomain, r.Service, r.Status, r.CNAME, r.Reason)
	}
	w.Flush()
}

// PrintCSV outputs results as CSV to stdout.
func PrintCSV(results []models.ScanResult) {
	w := csv.NewWriter(os.Stdout)
	_ = w.Write([]string{"subdomain", "cname", "service", "status", "reason"})
	for _, r := range results {
		_ = w.Write([]string{r.Subdomain, r.CNAME, r.Service, r.Status, r.Reason})
	}
	w.Flush()
}

// SaveJSON writes VULNERABLE results as indented JSON to the given file path.
func SaveJSON(results []models.ScanResult, path string) error {
	if results == nil {
		results = []models.ScanResult{}
	}
	data, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}
func WriteHTML(results []models.ScanResult, path string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	funcMap := template.FuncMap{
		"add": func(a, b int) int { return a + b },
	}

	tmpl, err := template.New("report").Funcs(funcMap).Parse(htmlTemplate)
	if err != nil {
		return err
	}

	var vulnerable, safe, unknown int
	for _, r := range results {
		switch r.Status {
		case "VULNERABLE":
			vulnerable++
		case "SAFE":
			safe++
		default:
			unknown++
		}
	}

	data := reportData{
		GeneratedAt: time.Now().Format("2006-01-02 15:04:05 MST"),
		Total:       len(results),
		Vulnerable:  vulnerable,
		Safe:        safe,
		Unknown:     unknown,
		Results:     results,
	}

	return tmpl.Execute(f, data)
}
