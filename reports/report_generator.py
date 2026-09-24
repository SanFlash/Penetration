"""Generate interactive JSON and self-contained HTML assessment reports."""
import html
import json
import os
from collections import Counter
from datetime import datetime, timezone

SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
SEVERITY_COLOR = {"Critical": "#ff4d6d", "High": "#ff8a4c", "Medium": "#ffc857", "Low": "#38e8a0", "Info": "#7d93ad"}


def _normalize_finding(finding: dict) -> dict:
    item = dict(finding)
    item.setdefault("confidence", "Medium")
    item.setdefault("category", "Web Application Security")
    item.setdefault("cwe", None)
    item.setdefault("owasp", None)
    item.setdefault("method", "GET")
    item.setdefault("parameter", None)
    item.setdefault("evidence", item.get("detail", ""))
    item.setdefault("impact", "Security or compatibility impact should be validated in the authorized test environment.")
    item.setdefault("remediation", "Review the affected code path and apply the appropriate control.")
    item.setdefault("references", [])
    return item


def generate(target: str, findings: list, evidence_dir: str, out_dir: str = "reports", metadata: dict | None = None) -> dict:
    os.makedirs(out_dir, exist_ok=True)
    normalized = [_normalize_finding(f) for f in findings]
    findings_sorted = sorted(normalized, key=lambda f: SEVERITY_ORDER.get(f.get("severity", "Info"), 5))
    summary = {sev: 0 for sev in SEVERITY_ORDER}
    categories = Counter()
    confidence = Counter()
    for f in findings_sorted:
        severity = f.get("severity", "Info")
        summary[severity] = summary.get(severity, 0) + 1
        categories[f.get("category", "Uncategorized")] += 1
        confidence[f.get("confidence", "Medium")] += 1

    meta = metadata or {}
    report = {
        "schema_version": "2.0",
        "target": target,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total_findings": len(findings_sorted),
        "severity_summary": summary,
        "category_summary": dict(categories),
        "confidence_summary": dict(confidence),
        "findings": findings_sorted,
        "evidence_directory": evidence_dir,
        "metadata": meta,
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

    findings_json = json.dumps(report["findings"], ensure_ascii=False).replace("</", "<\\/")
    categories_json = json.dumps(report["category_summary"], ensure_ascii=False)
    severity_json = json.dumps(report["severity_summary"], ensure_ascii=False)
    meta_json = json.dumps(report.get("metadata", {}), ensure_ascii=False)

    severity_cards = []
    for sev, count in report["severity_summary"].items():
        severity_cards.append(
            f'<div class="risk-card"><span style="--c:{SEVERITY_COLOR[sev]}"></span><small>{esc(sev)}</small><b>{count}</b></div>'
        )

    category_cards = []
    total = max(1, report["total_findings"])
    for category, count in report["category_summary"].items():
        pct = round(count / total * 100)
        category_cards.append(
            f'<div class="cat"><div><b>{esc(category)}</b><span>{count}</span></div><div class="catbar"><i style="width:{pct}%"></i></div></div>'
        )

    return f"""<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Sentinel Assessment Report</title>
<style>
:root{{--bg:#050810;--panel:#0b1220;--panel2:#0f1928;--line:#1d2d42;--text:#e6eff8;--muted:#8095ab;--accent:#38e8a0;--blue:#4ea1ff;--danger:#ff4d6d}}
*{{box-sizing:border-box}}body{{margin:0;background:radial-gradient(circle at 50% -10%,#132a44 0,#050810 42%,#02040a 100%);color:var(--text);font:14px/1.5 Inter,Segoe UI,Arial,sans-serif}}a{{color:#7dbaff}}button,input,select{{font:inherit}}button{{cursor:pointer}}
.shell{{max-width:1450px;margin:auto;padding:24px}}.hero{{border:1px solid var(--line);border-radius:22px;background:linear-gradient(135deg,#0b1727f2,#07101bf2);padding:26px;position:relative;overflow:hidden}}.hero:after{{content:"";position:absolute;width:360px;height:360px;border:1px solid #38e8a022;border-radius:50%;right:-120px;top:-180px;box-shadow:0 0 90px #38e8a015}}.eyebrow{{color:var(--accent);font-weight:800;letter-spacing:.14em;font-size:11px;text-transform:uppercase}}h1{{font-size:clamp(26px,4vw,46px);margin:7px 0}}.sub{{color:var(--muted);max-width:900px}}.meta{{display:flex;gap:12px;flex-wrap:wrap;margin-top:16px}}.chip{{border:1px solid var(--line);border-radius:999px;padding:7px 10px;background:#07101b;color:#b9c9d9}}
.nav{{display:flex;gap:8px;flex-wrap:wrap;margin:14px 0}}.nav button{{background:#08111d;color:#a9bdd1;border:1px solid var(--line);border-radius:9px;padding:9px 12px}}.nav button.active{{color:#06110d;background:var(--accent);border-color:var(--accent);font-weight:800}}
.grid{{display:grid;grid-template-columns:1.3fr .7fr;gap:14px;margin-top:14px}}.panel{{background:#09111ddd;border:1px solid var(--line);border-radius:16px;padding:16px;box-shadow:0 14px 50px #0005}}.section-title{{font-size:12px;color:#9bb0c6;letter-spacing:.12em;text-transform:uppercase;margin:0 0 13px}}
.riskgrid{{display:grid;grid-template-columns:repeat(5,1fr);gap:9px}}.risk-card{{position:relative;background:var(--panel2);border:1px solid var(--line);border-radius:12px;padding:13px;overflow:hidden}}.risk-card span{{position:absolute;left:0;top:0;width:4px;height:100%;background:var(--c)}}.risk-card small{{display:block;color:var(--muted)}}.risk-card b{{font-size:26px}}
.kpis{{display:grid;grid-template-columns:repeat(4,1fr);gap:9px}}.kpi{{padding:14px;background:var(--panel2);border:1px solid var(--line);border-radius:12px}}.kpi b{{display:block;font-size:25px}}.kpi span{{color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.08em}}
.cat{{padding:9px 0;border-bottom:1px solid #162438}}.cat>div:first-child{{display:flex;justify-content:space-between;gap:10px}}.cat span{{color:var(--muted)}}.catbar{{height:7px;background:#132033;border-radius:99px;overflow:hidden;margin-top:7px}}.catbar i{{display:block;height:100%;background:linear-gradient(90deg,var(--blue),var(--accent))}}
.controls{{display:flex;gap:9px;flex-wrap:wrap;margin-bottom:12px}}input,select{{background:#07101b;color:var(--text);border:1px solid var(--line);border-radius:9px;padding:9px 10px;min-height:40px}}input{{flex:1;min-width:220px}}
.finding{{border:1px solid var(--line);border-radius:13px;background:#08101b;padding:15px;margin:10px 0}}.fh{{display:flex;gap:8px;align-items:center;flex-wrap:wrap}}.badge{{border-radius:999px;padding:4px 8px;color:#06110d;font-weight:800;font-size:11px}}.fid{{color:var(--muted);font-family:Consolas,monospace;font-size:11px}}.finding h3{{margin:9px 0 4px;font-size:16px}}.finding .url{{color:#8aa1b8;word-break:break-all;font-size:12px}}details{{margin-top:10px}}summary{{cursor:pointer;color:#9fc1df}}pre{{background:#03070d;border:1px solid #142238;border-radius:9px;padding:11px;overflow:auto;white-space:pre-wrap;word-break:break-word;color:#bdd0e3}}.empty{{padding:35px;text-align:center;color:var(--muted)}}
.matrix{{overflow:auto}}table{{width:100%;border-collapse:collapse;min-width:600px}}th,td{{padding:9px;border-bottom:1px solid #17253a;text-align:left}}th{{color:var(--muted);font-size:11px;text-transform:uppercase}}
footer{{color:#62788f;text-align:center;padding:22px;font-size:12px}}
@media(max-width:900px){{.grid{{grid-template-columns:1fr}}.riskgrid{{grid-template-columns:repeat(2,1fr)}}.kpis{{grid-template-columns:repeat(2,1fr)}}.shell{{padding:12px}}}}@media(max-width:520px){{.riskgrid{{grid-template-columns:1fr 1fr}}.hero{{padding:18px}}.kpis{{grid-template-columns:1fr 1fr}}}}
</style></head><body><div class="shell">
<header class="hero"><div class="eyebrow">SENTINEL // PROFESSIONAL ASSESSMENT REPORT</div><h1>Interactive Web Assessment</h1><div class="sub">Evidence-driven compatibility and security observations with browser, responsive, accessibility, and category-level analysis.</div><div class="meta"><span class="chip">Target: {esc(report["target"])}</span><span class="chip">Generated: {esc(report["generated_at"])}</span><span class="chip">Schema: {esc(report["schema_version"])}</span></div></header>
<nav class="nav"><button class="active" data-tab="overview">Overview</button><button data-tab="findings">Findings</button><button data-tab="coverage">Coverage</button><button data-tab="evidence">Evidence</button></nav>
<section id="overview" class="tab">
<div class="panel"><div class="section-title">Severity distribution</div><div class="riskgrid">{''.join(severity_cards)}</div></div>
<div class="grid"><div class="panel"><div class="section-title">Assessment metrics</div><div class="kpis"><div class="kpi"><b>{report["total_findings"]}</b><span>Total findings</span></div><div class="kpi"><b>{len(report["category_summary"])}</b><span>Categories</span></div><div class="kpi"><b>{report["confidence_summary"].get("High",0)}</b><span>High confidence</span></div><div class="kpi"><b>{len(report.get("metadata",{}).get("compatibility",{}).get("results",[]))}</b><span>Browser checks</span></div></div></div>
<div class="panel"><div class="section-title">Category distribution</div>{''.join(category_cards) or '<div class="empty">No findings.</div>'}</div></div></section>
<section id="findings" class="tab" hidden><div class="panel"><div class="section-title">Findings explorer</div><div class="controls"><input id="search" placeholder="Search title, URL, category, evidence..."><select id="sev"><option value="">All severities</option><option>Critical</option><option>High</option><option>Medium</option><option>Low</option><option>Info</option></select><select id="cat"><option value="">All categories</option></select></div><div id="list"></div></div></section>
<section id="coverage" class="tab" hidden><div class="panel"><div class="section-title">Browser / viewport results</div><div class="matrix" id="matrix"></div></div></section>
<section id="evidence" class="tab" hidden><div class="panel"><div class="section-title">Evidence and execution metadata</div><pre id="meta"></pre><p><b>Evidence directory:</b> {esc(report["evidence_directory"])}</p><p>Generated screenshots and logs should be reviewed for sensitive data before sharing.</p></div></section>
<footer>Sentinel Assessment Framework • Automated results are observations requiring appropriate validation.</footer>
</div>
<script>
const findings={findings_json};const meta={meta_json};const severity={severity_json};const categories={categories_json};const colors={json.dumps(SEVERITY_COLOR)};
const esc=function(v){{return String(v==null?"":v).replace(/[&<>"']/g,function(c){{return {{"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}}[c]}})}};
const tabs=document.querySelectorAll(".nav button");tabs.forEach(function(b){{b.addEventListener("click",function(){{tabs.forEach(x=>x.classList.remove("active"));b.classList.add("active");document.querySelectorAll(".tab").forEach(x=>x.hidden=x.id!==b.dataset.tab);}})}});
const cat=document.getElementById("cat");Object.keys(categories).sort().forEach(function(c){{const o=document.createElement("option");o.value=c;o.textContent=c;cat.appendChild(o)}});
function renderFindings(){{const q=document.getElementById("search").value.toLowerCase();const s=document.getElementById("sev").value;const c=cat.value;const list=document.getElementById("list");const filtered=findings.filter(function(f){{const hay=JSON.stringify(f).toLowerCase();return (!q||hay.includes(q))&&(!s||f.severity===s)&&(!c||f.category===c)}});if(!filtered.length){{list.innerHTML='<div class="empty">No matching findings.</div>';return}}list.innerHTML=filtered.map(function(f){{const color=colors[f.severity]||colors.Info;return '<article class="finding"><div class="fh"><span class="badge" style="background:'+color+'">'+esc(f.severity)+'</span><span class="fid">'+esc(f.id)+'</span><span class="fid">'+esc(f.confidence)+' confidence</span></div><h3>'+esc(f.title)+'</h3><div class="url">'+esc(f.url)+'</div><details><summary>Evidence / impact / remediation</summary><p><b>Category:</b> '+esc(f.category)+' &nbsp; <b>CWE:</b> '+esc(f.cwe||"-")+' &nbsp; <b>OWASP:</b> '+esc(f.owasp||"-")+'</p><pre>'+esc(f.evidence)+'</pre>'+ (f.screenshot ? '<div style="margin-top:12px"><b>Marked screenshot:</b><br><a href="../'+esc(String(f.screenshot).replace(/\\/g,"/"))+'" target="_blank" rel="noopener"><img src="../'+esc(String(f.screenshot).replace(/\\/g,"/"))+'" alt="Marked evidence screenshot" style="max-width:100%;border:1px solid #263b55;border-radius:10px;margin-top:8px"></a></div>' : '') + '<p><b>Impact:</b> '+esc(f.impact)+'</p><p><b>Remediation:</b> '+esc(f.remediation)+'</p></details></article>'}}).join("")}}
["search","sev"].forEach(function(id){{document.getElementById(id).addEventListener("input",renderFindings)}});cat.addEventListener("change",renderFindings);renderFindings();
const rows=(meta.compatibility&&meta.compatibility.results)||[];document.getElementById("matrix").innerHTML=rows.length?'<table><thead><tr><th>Browser</th><th>Viewport</th><th>Status</th><th>Load</th><th>Console</th><th>Network</th><th>Overflow</th></tr></thead><tbody>'+rows.map(function(r){{return '<tr><td>'+esc(r.browser)+'</td><td>'+esc(r.viewport)+'</td><td>'+esc(r.status)+'</td><td>'+esc(r.load_ms)+' ms</td><td>'+r.console_errors.length+'</td><td>'+r.request_failures.length+'</td><td>'+ (r.horizontal_overflow?"YES":"NO")+'</td></tr>'}}).join("")+'</tbody></table>':'<div class="empty">No browser matrix metadata recorded.</div>';
document.getElementById("meta").textContent=JSON.stringify(meta,null,2);
</script></body></html>"""
