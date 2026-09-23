"""Generate machine-readable JSON and a self-contained HTML assessment report."""
import html
import json
import os
from datetime import datetime, timezone

SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
SEVERITY_COLOR = {
    "Critical": "#8A1E1E", "High": "#B8501E", "Medium": "#B7891E",
    "Low": "#1E7A46", "Info": "#6B7280",
}


def _normalize_finding(finding: dict) -> dict:
    """Give every finding a predictable schema without changing its detector data."""
    item = dict(finding)
    item.setdefault("confidence", "Medium")
    item.setdefault("category", "Web Application Security")
    item.setdefault("cwe", None)
    item.setdefault("owasp", None)
    item.setdefault("method", "GET")
    item.setdefault("parameter", None)
    item.setdefault("evidence", item.get("detail", ""))
    item.setdefault("impact", "Security impact should be validated in the authorized test environment.")
    item.setdefault("remediation", "Review the affected code path and apply the appropriate server-side control.")
    item.setdefault("references", [])
    return item


def generate(target: str, findings: list, evidence_dir: str, out_dir: str = "reports") -> dict:
    os.makedirs(out_dir, exist_ok=True)
    normalized = [_normalize_finding(f) for f in findings]
    findings_sorted = sorted(
        normalized,
        key=lambda f: SEVERITY_ORDER.get(f.get("severity", "Info"), 5),
    )

    summary = {sev: 0 for sev in SEVERITY_ORDER}
    for f in findings_sorted:
        severity = f.get("severity", "Info")
        summary[severity] = summary.get(severity, 0) + 1

    report = {
        "schema_version": "1.1",
        "target": target,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total_findings": len(findings_sorted),
        "severity_summary": summary,
        "findings": findings_sorted,
        "evidence_directory": evidence_dir,
    }

    json_path = os.path.join(out_dir, "findings.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)

    html_path = os.path.join(out_dir, "report.html")
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(_render_html(report))

    return {"json_path": json_path, "html_path": html_path, "report": report}


def _render_html(report: dict) -> str:
    def esc(value):
        return html.escape("" if value is None else str(value))

    rows = []
    for finding in report["findings"]:
        severity = finding.get("severity", "Info")
        color = SEVERITY_COLOR.get(severity, "#6B7280")
        refs = finding.get("references") or []
        refs_html = "<br>".join(f'<a href="{esc(r)}">{esc(r)}</a>' for r in refs)
        rows.append(f"""
        <article class="finding">
          <div class="finding-head">
            <span class="badge" style="background:{color}">{esc(severity)}</span>
            <span class="id">{esc(finding.get("id"))}</span>
            <h2>{esc(finding.get("title"))}</h2>
          </div>
          <dl>
            <dt>URL</dt><dd><code>{esc(finding.get("url"))}</code></dd>
            <dt>Confidence</dt><dd>{esc(finding.get("confidence"))}</dd>
            <dt>Category</dt><dd>{esc(finding.get("category"))}</dd>
            <dt>CWE</dt><dd>{esc(finding.get("cwe"))}</dd>
            <dt>OWASP</dt><dd>{esc(finding.get("owasp"))}</dd>
            <dt>Parameter</dt><dd>{esc(finding.get("parameter"))}</dd>
          </dl>
          <section><h3>Evidence</h3><pre>{esc(finding.get("evidence"))}</pre></section>
          <section><h3>Impact</h3><p>{esc(finding.get("impact"))}</p></section>
          <section><h3>Remediation</h3><p>{esc(finding.get("remediation"))}</p></section>
          {f'<section><h3>References</h3><p>{refs_html}</p></section>' if refs_html else ''}
        </article>
        """)

    summary_cells = "".join(
        f'<div class="summary-card"><strong>{esc(sev)}</strong><span>{count}</span></div>'
        for sev, count in report["severity_summary"].items() if count
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Web Application Penetration Test Report</title>
<style>
body {{ font-family: -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif; margin:0; background:#F4F7FB; color:#172033; }}
main {{ max-width:1100px; margin:0 auto; padding:32px 20px 60px; }}
header {{ background:#0B2545; color:white; border-radius:14px; padding:28px; }}
header h1 {{ margin:0 0 8px; }}
.meta {{ opacity:.9; word-break:break-word; }}
.summary {{ display:flex; flex-wrap:wrap; gap:12px; margin:20px 0; }}
.summary-card {{ background:white; border:1px solid #D8E0EA; border-radius:10px; padding:12px 16px; min-width:100px; display:flex; justify-content:space-between; gap:18px; }}
.finding {{ background:white; border:1px solid #D8E0EA; border-radius:12px; padding:20px; margin:16px 0; box-shadow:0 2px 8px rgba(11,37,69,.05); }}
.finding-head {{ display:flex; align-items:center; flex-wrap:wrap; gap:10px; }}
.finding-head h2 {{ margin:0; flex:1 1 100%; font-size:1.2rem; }}
.badge {{ color:white; padding:4px 9px; border-radius:999px; font-weight:700; font-size:.8rem; }}
.id {{ font-family:monospace; color:#536273; }}
dl {{ display:grid; grid-template-columns:120px 1fr; gap:7px 14px; }}
dt {{ font-weight:700; color:#536273; }}
dd {{ margin:0; word-break:break-word; }}
pre {{ background:#101827; color:#E8EEF7; padding:14px; border-radius:8px; overflow:auto; white-space:pre-wrap; word-break:break-word; }}
code {{ word-break:break-all; }}
a {{ color:#0B5CAD; }}
@media(max-width:640px) {{ main{{padding:16px 10px 40px}} header{{padding:20px}} dl{{grid-template-columns:1fr}} .finding{{padding:15px}} }}
</style>
</head>
<body><main>
<header>
<h1>Web Application Penetration Test Report</h1>
<div class="meta"><b>Target:</b> {esc(report["target"])}<br>
<b>Generated:</b> {esc(report["generated_at"])}<br>
<b>Total findings:</b> {report["total_findings"]}</div>
</header>
<div class="summary">{summary_cells}</div>
<section>
{''.join(rows) if rows else '<p>No findings were recorded.</p>'}
</section>
</main></body></html>"""
