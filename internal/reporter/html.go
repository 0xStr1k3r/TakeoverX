package reporter

import (
	"fmt"
	"html/template"
	"io"

	"github.com/0xStr1k3r/TakeoverX/internal/models"
)

// htmlTemplate is fully self-contained: no CDN, no external stylesheet, no
// web fonts. A report has to stay readable months later, on a machine with no
// network, and when the recipient is not technical enough to run a web server.
var htmlTemplate = template.Must(template.New("report").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>TakeoverX — {{.Target}}</title>
<style>
  :root{
    --bg:#0f1115; --panel:#171a21; --line:#242833; --fg:#e6e8ee; --muted:#9aa3b2;
    --crit:#ff5c5c; --warn:#ffb020; --ok:#3ddc97; --info:#5aa9ff;
  }
  @media (prefers-color-scheme: light){
    :root{ --bg:#f6f7f9; --panel:#fff; --line:#e3e6ec; --fg:#1b1f27; --muted:#5b6472;
           --crit:#c62828; --warn:#b26a00; --ok:#1b7a4b; --info:#1565c0; }
  }
  *{box-sizing:border-box}
  body{margin:0;padding:2rem 1rem;background:var(--bg);color:var(--fg);
       font:15px/1.6 ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
  main{max-width:1080px;margin:0 auto}
  h1{font-size:1.6rem;margin:0 0 .25rem}
  h2{font-size:1.1rem;margin:2rem 0 .75rem}
  .sub{color:var(--muted);font-size:.9rem;margin-bottom:1.5rem}
  .tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:.75rem;margin:1.25rem 0}
  .tile{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:.9rem 1rem}
  .tile .n{font-size:1.7rem;font-weight:650;line-height:1.2}
  .tile .l{color:var(--muted);font-size:.78rem;text-transform:uppercase;letter-spacing:.05em;margin-top:.2rem}
  .tile.crit .n{color:var(--crit)} .tile.warn .n{color:var(--warn)}
  .tile.ok .n{color:var(--ok)} .tile.info .n{color:var(--info)}
  table{width:100%;border-collapse:collapse;background:var(--panel);
        border:1px solid var(--line);border-radius:10px;overflow:hidden}
  th,td{text-align:left;padding:.6rem .75rem;border-bottom:1px solid var(--line);vertical-align:top}
  th{font-size:.75rem;text-transform:uppercase;letter-spacing:.05em;color:var(--muted);font-weight:600}
  tr:last-child td{border-bottom:none}
  code,.mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:.86em;word-break:break-all}
  .pill{display:inline-block;padding:.1rem .5rem;border-radius:999px;font-size:.72rem;
        font-weight:650;letter-spacing:.03em;white-space:nowrap}
  .p-crit{background:rgba(255,92,92,.15);color:var(--crit)}
  .p-warn{background:rgba(255,176,32,.15);color:var(--warn)}
  .p-ok{background:rgba(61,220,151,.15);color:var(--ok)}
  .p-mute{background:rgba(154,163,178,.15);color:var(--muted)}
  .finding{background:var(--panel);border:1px solid var(--line);border-left:3px solid var(--crit);
           border-radius:10px;padding:1rem 1.15rem;margin-bottom:.85rem}
  .finding.medium{border-left-color:var(--warn)}
  .finding h3{margin:0 0 .35rem;font-size:1rem}
  .kv{color:var(--muted);font-size:.85rem;margin-top:.5rem}
  .kv div{margin-top:.2rem}
  .empty{background:var(--panel);border:1px solid var(--line);border-radius:10px;
         padding:2rem;text-align:center;color:var(--muted)}
  a{color:var(--info)}
  footer{margin-top:2.5rem;color:var(--muted);font-size:.8rem;border-top:1px solid var(--line);padding-top:1rem}
</style>
</head>
<body>
<main>
  <h1>Subdomain takeover scan</h1>
  <div class="sub">{{.Target}} &middot; {{.Started}} &middot; completed in {{.DurationStr}}</div>

  <div class="tiles">
    <div class="tile"><div class="n">{{.Summary.Total}}</div><div class="l">Names checked</div></div>
    <div class="tile crit"><div class="n">{{.Summary.Vulnerable}}</div><div class="l">Takeover risk</div></div>
    <div class="tile warn"><div class="n">{{.Summary.High}}</div><div class="l">High confidence</div></div>
    <div class="tile info"><div class="n">{{.Summary.Medium}}</div><div class="l">Medium confidence</div></div>
    <div class="tile ok"><div class="n">{{.Summary.Safe}}</div><div class="l">Claimed</div></div>
    <div class="tile"><div class="n">{{.Summary.Unknown}}</div><div class="l">Inconclusive</div></div>
  </div>

  {{if .Notes}}
  <h2>Scan notes</h2>
  <div class="empty">
    {{range .Notes}}<div>{{.}}</div>{{end}}
  </div>
  {{end}}

  {{if .Summary.Vulnerable}}
  <h2>Findings ({{.Summary.Vulnerable}})</h2>
  {{range .Results}}{{if .Vulnerable}}
  <div class="finding {{if eq .Confidence "MEDIUM"}}medium{{end}}">
    <h3>{{.Subdomain}}</h3>
    <div>
      <span class="pill p-crit">{{.Service}}</span>
      <span class="pill {{if eq .Confidence "MEDIUM"}}p-warn{{else}}p-crit{{end}}">{{.Confidence}} confidence</span>
      {{if .Severity}}<span class="pill p-mute">{{.Severity}} impact</span>{{end}}
    </div>
    <div class="kv">
      <div><strong>Why:</strong> {{.Reason}}</div>
      {{if .CNAMEChain}}<div><strong>CNAME chain:</strong> <span class="mono">{{.CNAMEChain}}</span></div>{{end}}
      {{if .Remediation}}<div><strong>Fix:</strong> {{.Remediation}}</div>{{end}}
      {{if .DocsURL}}<div><strong>Provider docs:</strong> <a href="{{.DocsURL}}" rel="noopener noreferrer nofollow">{{.DocsURL}}</a></div>{{end}}
    </div>
  </div>
  {{end}}{{end}}{{end}}

  <h2>All results</h2>
  <table>
    <thead><tr>
      <th>Subdomain</th><th>Status</th><th>Confidence</th><th>Service</th><th>Record</th><th>Evidence</th>
    </tr></thead>
    <tbody>
    {{range .Results}}
      <tr>
        <td class="mono">{{.Subdomain}}</td>
        <td><span class="pill {{if .Vulnerable}}p-crit{{else if eq .Status "SAFE"}}p-ok{{else}}p-mute{{end}}">{{.Status}}</span></td>
        <td>{{.Confidence}}</td>
        <td>{{.Service}}</td>
        <td class="mono">{{.RecordType}}</td>
        <td>{{.Reason}}</td>
      </tr>
    {{end}}
    </tbody>
  </table>

  <footer>
    Generated by TakeoverX &middot; {{.Services}} provider fingerprints loaded.
    Findings require explicit written authorisation for the assets involved.
  </footer>
</main>
</body>
</html>
`))

// WriteHTML renders the standalone HTML report to w.
func WriteHTMLTo(w io.Writer, r *Report) error {
	if err := htmlTemplate.Execute(w, r); err != nil {
		return fmt.Errorf("rendering HTML report: %w", err)
	}
	return nil
}

// FindingsOnly filters a report down to actionable results, for --only-findings.
func FindingsOnly(r *Report) *Report {
	out := *r
	// An empty slice rather than nil: nil marshals to JSON null, which breaks
	// every consumer that iterates the array without a null check.
	out.Results = []models.ScanResult{}
	for _, s := range r.Results {
		if s.Vulnerable() {
			out.Results = append(out.Results, s)
		}
	}
	out.Summary.Vulnerable = len(out.Results)
	out.Summary.High, out.Summary.Medium = 0, 0
	for _, s := range out.Results {
		if s.Confidence == string(models.ConfidenceHigh) {
			out.Summary.High++
		} else {
			out.Summary.Medium++
		}
	}
	return &out
}
