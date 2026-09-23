"""
reports/report_generator.py — turns the findings collected during a run
into findings.json and a readable, self-contained report.html.
"""
import json
import os
from datetime import datetime, timezone

SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
SEVERITY_COLOR = {
    "Critical": "#8A1E1E", "High": "#B8501E", "Medium": "#B7891E",
    "Low": "#1E7A46", "Info": "#6B7280",
}


def generate(target: str, findings: list, evidence_dir: str, out_dir: str = "reports") -> dict:
    os.makedirs(out_dir, exist_ok=True)
    findings_sorted = sorted(findings, key=lambda f: SEVERITY_ORDER.get(f["severity"], 5))

    summary = {sev: 0 for sev in SEVERITY_ORDER}
    for f in findings_sorted:
        summary[f["severity"]] = summary.get(f["severity"], 0) + 1

    report = {
        "target": target,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total_findings": len(findings_sorted),
        "severity_summary": summary,
        "findings": findings_sorted,
    }

    json_path = os.path.join(out_dir, "findings.json")
    with open(json_path, "w") as f:
        json.dump(report, f, indent=2)

    html_path = os.path.join(out_dir, "report.html")
    with open(html_path, "w") as f:
        f.write(_render_html(report))

    return {"json_path": json_path, "html_path": html_path, "report": report}


def _render_html(report: dict) -> str:
    rows = ""
    for finding in report["findings"]:
        color = SEVERITY_COLOR.get(finding["severity"], "#6B7280")
        rows += f"""
        <tr>
          <td><span style="background:{color};color:white;padding:2px 8px;
              border-radius:4px;font-weight:bold;">{finding['severity']}</span></td>
          <td>{finding['id']}</td>
          <td>{finding['title']}</td>
          <td><code>{finding['url']}</code></td>
          <td>{finding['detail']}</td>
        </tr>"""

    summary_cells = "".join(
        f'<div style="display:inline-block;margin-right:16px;">'
        f'<b style="color:{SEVERITY_COLOR.get(sev, "#6B7280")}">{sev}</b>: {count}</div>'
        for sev, count in report["severity_summary"].items() if count
    )

    return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Pentest Report — {report['target']}</title>
<style>
body {{ font-family: -apple-system, Segoe UI, sans-serif; margin: 40px; color: #0B2545; }}
h1 {{ color: #0B2545; }}
table {{ border-collapse: collapse; width: 100%; margin-top: 20px; }}
th, td {{ border: 1px solid #D5DEE8; padding: 10px; text-align: left; vertical-align: top; }}
th {{ background: #0B2545; color: white; }}
tr:nth-child(even) {{ background: #F5F8FC; }}
code {{ font-size: 0.85em; }}
</style></head>
<body>
<h1>Web Application Penetration Test Report</h1>
<p><b>Target:</b> {report['target']}<br>
<b>Generated:</b> {report['generated_at']}<br>
<b>Total findings:</b> {report['total_findings']}</p>
<div>{summary_cells}</div>
<table>
<tr><th>Severity</th><th>ID</th><th>Title</th><th>URL</th><th>Detail</th></tr>
{rows}
</table>
</body></html>"""
