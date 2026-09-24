"""Generate interactive JSON and self-contained HTML assessment reports."""
import html
import json
import os
from collections import Counter
from datetime import datetime, timezone


SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
SEVERITY_COLOR = {
    "Critical": "#ff4d6d",
    "High": "#ff8a4c",
    "Medium": "#ffc857",
    "Low": "#38e8a0",
    "Info": "#7d93ad",
}


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


def _compatibility_meta(metadata: dict) -> dict:
    return (
        metadata.get("ui_responsive")
        or metadata.get("compatibility")
        or {}
    )


def _safe_relative_path(path: str, out_dir: str) -> str | None:
    if not path:
        return None
    path = os.path.normpath(str(path))
    if not os.path.exists(path):
        if path.startswith("evidence" + os.sep) or path.startswith("evidence/"):
            return "../" + path.replace("\\", "/")
        return None
    try:
        rel = os.path.relpath(path, out_dir)
    except ValueError:
        return None
    return rel.replace("\\", "/")


def _collect_gallery(evidence_dir: str, out_dir: str, findings: list[dict]) -> list[dict]:
    gallery = []
    if os.path.isdir(evidence_dir):
        for root, _, files in os.walk(evidence_dir):
            for name in sorted(files):
                if not name.lower().endswith((".png", ".jpg", ".jpeg", ".webp")):
                    continue
                path = os.path.join(root, name)
                rel = _safe_relative_path(path, out_dir)
                if not rel:
                    continue
                gallery.append({
                    "name": name,
                    "path": rel,
                    "kind": "failure" if "failure" in name.lower() else "evidence",
                    "size": os.path.getsize(path),
                })

    known = {item["path"] for item in gallery}
    for finding in findings:
        screenshot = finding.get("screenshot")
        rel = _safe_relative_path(screenshot, out_dir) if screenshot else None
        if rel and rel not in known:
            gallery.append({
                "name": os.path.basename(str(screenshot)),
                "path": rel,
                "kind": "failure" if "failure" in str(screenshot).lower() else "finding",
                "size": os.path.getsize(screenshot) if os.path.exists(screenshot) else 0,
            })
            known.add(rel)
    return gallery


def generate(target: str, findings: list, evidence_dir: str, out_dir: str = "reports", metadata: dict | None = None) -> dict:
    os.makedirs(out_dir, exist_ok=True)
    normalized = [_normalize_finding(f) for f in findings]

    # Collapse repeated viewport observations into one finding while preserving
    # every screenshot/occurrence for evidence review.
    grouped = {}
    for item in normalized:
        fid = str(item.get("id", ""))
        base_url = str(item.get("url", "")).split("?", 1)[0] if fid.startswith("COMP-") else str(item.get("url", ""))
        evidence = str(item.get("evidence", ""))
        if fid.startswith("COMP-") and ": " in evidence:
            evidence = evidence.split(": ", 1)[1]
        key = (
            item.get("title"),
            item.get("category"),
            base_url,
            item.get("parameter"),
            evidence,
        )
        if key not in grouped:
            first = dict(item)
            first["occurrences"] = 1
            first["screenshots"] = []
            if item.get("screenshot"):
                first["screenshots"].append(item["screenshot"])
            first["viewports"] = []
            grouped[key] = first
        else:
            current = grouped[key]
            current["occurrences"] += 1
            if item.get("screenshot") and item["screenshot"] not in current["screenshots"]:
                current["screenshots"].append(item["screenshot"])
            vp = item.get("evidence", "")
            if "/" in vp:
                current_viewport = vp.split(":", 1)[0]
                if current_viewport not in current["viewports"]:
                    current["viewports"].append(current_viewport)

    normalized = list(grouped.values())
    for item in normalized:
        if item.get("screenshots"):
            item["screenshot"] = item["screenshots"][0]
        item["viewports"] = sorted(set(item.get("viewports", [])))

    findings_sorted = sorted(
        normalized,
        key=lambda f: (SEVERITY_ORDER.get(f.get("severity", "Info"), 5), f.get("category", ""), f.get("title", "")),
    )

    summary = {sev: 0 for sev in SEVERITY_ORDER}
    categories = Counter()
    confidence = Counter()
    for finding in findings_sorted:
        severity = finding.get("severity", "Info")
        summary[severity] = summary.get(severity, 0) + 1
        categories[finding.get("category", "Uncategorized")] += 1
        confidence[finding.get("confidence", "Medium")] += 1

    meta = metadata or {}
    compatibility = _compatibility_meta(meta)
    browser_results = compatibility.get("results", [])
    security_evidence = meta.get("security_evidence", [])
    gallery = _collect_gallery(evidence_dir, out_dir, findings_sorted)

    for finding in findings_sorted:
        if finding.get("screenshot"):
            finding["screenshot_relative"] = _safe_relative_path(finding["screenshot"], out_dir)
        finding["screenshots_relative"] = [
            rel for rel in (
                _safe_relative_path(path, out_dir)
                for path in finding.get("screenshots", [])
            ) if rel
        ]

    report = {
        "schema_version": "3.0",
        "target": target,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total_findings": len(findings_sorted),
        "severity_summary": summary,
        "category_summary": dict(categories),
        "confidence_summary": dict(confidence),
        "findings": findings_sorted,
        "evidence_directory": evidence_dir,
        "evidence_gallery": gallery,
        "browser_coverage": {
            "browser": "chromium",
            "checks": len(browser_results),
            "urls": len(compatibility.get("urls_tested", [])),
            "viewports": len(compatibility.get("viewports", {})),
            "failures": sum(1 for r in browser_results if (r.get("status") or 0) >= 400),
            "marked": sum(1 for r in browser_results if r.get("evidence_marked")),
        },
        "security_evidence": security_evidence,
        "metadata": meta,
    }

    json_path = os.path.join(out_dir, "findings.json")
    with open(json_path, "w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2, ensure_ascii=False)

    manifest_path = os.path.join(out_dir, "evidence_manifest.json")
    with open(manifest_path, "w", encoding="utf-8") as handle:
        json.dump({
            "target": target,
            "generated_at": report["generated_at"],
            "screenshots": gallery,
            "security_captures": security_evidence,
        }, handle, indent=2, ensure_ascii=False)

    html_path = os.path.join(out_dir, "report.html")
    with open(html_path, "w", encoding="utf-8") as handle:
        handle.write(_render_html(report))
    return {
        "json_path": json_path,
        "html_path": html_path,
        "manifest_path": manifest_path,
        "report": report,
    }


def _render_html(report: dict) -> str:
    findings_json = json.dumps(report["findings"], ensure_ascii=False).replace("</", "<\\/")
    gallery_json = json.dumps(report["evidence_gallery"], ensure_ascii=False)
    coverage_json = json.dumps(report["metadata"].get("ui_responsive") or report["metadata"].get("compatibility") or {}, ensure_ascii=False)
    security_json = json.dumps(report.get("security_evidence", []), ensure_ascii=False)
    meta_json = json.dumps(report.get("metadata", {}), ensure_ascii=False)

    cards = []
    for severity, count in report["severity_summary"].items():
        cards.append(
            '<div class="risk-card"><span style="--c:%s"></span><small>%s</small><b>%s</b></div>'
            % (SEVERITY_COLOR[severity], html.escape(severity), count)
        )

    category_cards = []
    total = max(1, report["total_findings"])
    for category, count in report["category_summary"].items():
        pct = round(count / total * 100)
        category_cards.append(
            '<div class="cat"><div><b>%s</b><span>%s</span></div><div class="catbar"><i style="width:%s%%"></i></div></div>'
            % (html.escape(category), count, pct)
        )

    browser = report["browser_coverage"]
    failed_screens = sum(1 for x in report["evidence_gallery"] if x["kind"] == "failure")
    template = r'''<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Sentinel Assessment Report</title>
<style>
:root{--bg:#050810;--panel:#0b1220;--panel2:#0f1928;--line:#1d2d42;--text:#e6eff8;--muted:#8095ab;--accent:#38e8a0;--blue:#4ea1ff;--danger:#ff4d6d;--warn:#ffc857}
*{box-sizing:border-box}body{margin:0;background:radial-gradient(circle at 50% -10%,#132a44 0,#050810 42%,#02040a 100%);color:var(--text);font:14px/1.5 Inter,Segoe UI,Arial,sans-serif}
a{color:#8fc5ff}.shell{max-width:1500px;margin:auto;padding:22px}.hero{border:1px solid var(--line);border-radius:22px;background:linear-gradient(135deg,#0b1727f2,#07101bf2);padding:26px;position:relative;overflow:hidden}.hero:after{content:"";position:absolute;width:360px;height:360px;border:1px solid #38e8a022;border-radius:50%;right:-120px;top:-180px;box-shadow:0 0 90px #38e8a015}
.eyebrow{color:var(--accent);font-weight:800;letter-spacing:.14em;font-size:11px;text-transform:uppercase}h1{font-size:clamp(26px,4vw,46px);margin:7px 0}.sub{color:var(--muted);max-width:980px}.meta{display:flex;gap:10px;flex-wrap:wrap;margin-top:16px}.chip{border:1px solid var(--line);border-radius:999px;padding:7px 10px;background:#07101b;color:#b9c9d9}
.nav{display:flex;gap:8px;flex-wrap:wrap;margin:14px 0}.nav button{background:#08111d;color:#a9bdd1;border:1px solid var(--line);border-radius:9px;padding:9px 12px}.nav button.active{color:#06110d;background:var(--accent);border-color:var(--accent);font-weight:800}
.panel{background:#09111ddd;border:1px solid var(--line);border-radius:16px;padding:16px;box-shadow:0 14px 50px #0005;margin-bottom:14px}.section-title{font-size:12px;color:#9bb0c6;letter-spacing:.12em;text-transform:uppercase;margin:0 0 13px}
.grid{display:grid;grid-template-columns:1.25fr .75fr;gap:14px}.riskgrid{display:grid;grid-template-columns:repeat(5,1fr);gap:9px}.risk-card{position:relative;background:var(--panel2);border:1px solid var(--line);border-radius:12px;padding:13px;overflow:hidden}.risk-card span{position:absolute;left:0;top:0;width:4px;height:100%;background:var(--c)}.risk-card small{display:block;color:var(--muted)}.risk-card b{font-size:26px}
.kpis{display:grid;grid-template-columns:repeat(4,1fr);gap:9px}.kpi{padding:14px;background:var(--panel2);border:1px solid var(--line);border-radius:12px}.kpi b{display:block;font-size:25px}.kpi span{color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.08em}
.cat{padding:9px 0;border-bottom:1px solid #162438}.cat>div:first-child{display:flex;justify-content:space-between;gap:10px}.cat span{color:var(--muted)}.catbar{height:7px;background:#132033;border-radius:99px;overflow:hidden;margin-top:7px}.catbar i{display:block;height:100%;background:linear-gradient(90deg,var(--blue),var(--accent))}
.controls{display:flex;gap:9px;flex-wrap:wrap;margin-bottom:12px}input,select{background:#07101b;color:var(--text);border:1px solid var(--line);border-radius:9px;padding:9px 10px;min-height:40px}input{flex:1;min-width:220px}
.finding{border:1px solid var(--line);border-radius:13px;background:#08101b;padding:15px;margin:10px 0}.fh{display:flex;gap:8px;align-items:center;flex-wrap:wrap}.badge{border-radius:999px;padding:4px 8px;color:#06110d;font-weight:800;font-size:11px}.fid{color:var(--muted);font-family:Consolas,monospace;font-size:11px}.finding h3{margin:9px 0 4px;font-size:16px}.finding .url{color:#8aa1b8;word-break:break-all;font-size:12px}details{margin-top:10px}summary{cursor:pointer;color:#9fc1df}pre{background:#03070d;border:1px solid #142238;border-radius:9px;padding:11px;overflow:auto;white-space:pre-wrap;word-break:break-word;color:#bdd0e3}.empty{padding:35px;text-align:center;color:var(--muted)}
.matrix{overflow:auto}table{width:100%;border-collapse:collapse;min-width:720px}th,td{padding:9px;border-bottom:1px solid #17253a;text-align:left;vertical-align:top}th{color:var(--muted);font-size:11px;text-transform:uppercase}.ok{color:var(--accent)}.fail{color:var(--danger)}.warn{color:var(--warn)}
.gallery{display:grid;grid-template-columns:repeat(3,1fr);gap:12px}.shot{border:1px solid var(--line);background:#07101b;border-radius:12px;padding:9px}.shot img{width:100%;aspect-ratio:16/10;object-fit:cover;border-radius:8px;border:1px solid #1a2a40}.shot .caption{font-size:12px;margin-top:7px;word-break:break-word}.shot.failure{border-color:#6b2436}.shot.failure .caption{color:#ff8da3}.tag{display:inline-block;border-radius:99px;padding:3px 7px;font-size:10px;font-weight:800;background:#142237;color:#a9bdd1;margin-bottom:5px}.tag.failure{background:#45182a;color:#ff9ab0}
.summary-strip{display:grid;grid-template-columns:repeat(4,1fr);gap:9px;margin-top:10px}.summary-item{padding:12px;background:#07101b;border:1px solid var(--line);border-radius:11px}.summary-item b{display:block;font-size:22px}.summary-item span{color:var(--muted);font-size:11px}
footer{color:#62788f;text-align:center;padding:22px;font-size:12px}
@media(max-width:950px){.grid{grid-template-columns:1fr}.gallery{grid-template-columns:repeat(2,1fr)}.riskgrid{grid-template-columns:repeat(2,1fr)}.kpis,.summary-strip{grid-template-columns:repeat(2,1fr)}.shell{padding:12px}}
@media(max-width:560px){.gallery{grid-template-columns:1fr}.hero{padding:18px}.kpis,.summary-strip{grid-template-columns:1fr 1fr}}
</style>
</head>
<body>
<div class="shell">
<header class="hero">
<div class="eyebrow">SENTINEL // PROFESSIONAL ASSESSMENT REPORT</div>
<h1>Interactive Web Assessment</h1>
<div class="sub">Evidence-driven Chrome compatibility, attack-surface mutation, security controls, and visual failure evidence.</div>
<div class="meta">
<span class="chip">Target: __TARGET__</span>
<span class="chip">Generated: __GENERATED__</span>
<span class="chip">Schema: __SCHEMA__</span>
<span class="chip">Profile: __PROFILE__</span>
</div>
</header>

<nav class="nav">
<button class="active" data-tab="overview">Overview</button>
<button data-tab="findings">Findings</button>
<button data-tab="coverage">Coverage</button>
<button data-tab="evidence">Evidence</button>
<button data-tab="execution">Execution</button>
</nav>

<section id="overview" class="tab">
<div class="panel"><div class="section-title">Severity distribution</div><div class="riskgrid">__CARDS__</div></div>
<div class="grid">
<div class="panel"><div class="section-title">Assessment metrics</div><div class="kpis">
<div class="kpi"><b>__TOTAL__</b><span>Total findings</span></div>
<div class="kpi"><b>__CATEGORIES__</b><span>Categories</span></div>
<div class="kpi"><b>__HIGHCONF__</b><span>High confidence</span></div>
<div class="kpi"><b>__CHECKS__</b><span>Chrome checks</span></div>
</div></div>
<div class="panel"><div class="section-title">Category distribution</div>__CATEGORIES_HTML__</div>
</div>
<div class="panel"><div class="section-title">Evidence health</div><div class="summary-strip">
<div class="summary-item"><b>__SCREENSHOTS__</b><span>Evidence screenshots</span></div>
<div class="summary-item"><b>__FAILSCREENS__</b><span>Failure screenshots</span></div>
<div class="summary-item"><b>__MARKED__</b><span>Marked Chrome checks</span></div>
<div class="summary-item"><b>__SECURITYCAPS__</b><span>Security captures</span></div>
</div></div>
</section>

<section id="findings" class="tab" hidden>
<div class="panel"><div class="section-title">Findings explorer</div>
<div class="controls"><input id="search" placeholder="Search title, URL, category, evidence..."><select id="sev"><option value="">All severities</option><option>Critical</option><option>High</option><option>Medium</option><option>Low</option><option>Info</option></select><select id="cat"><option value="">All categories</option></select></div>
<div id="list"></div></div>
</section>

<section id="coverage" class="tab" hidden>
<div class="panel"><div class="section-title">Chrome / viewport coverage</div>
<div class="summary-strip"><div class="summary-item"><b>__CHECKS__</b><span>Browser checks</span></div><div class="summary-item"><b>__URLS__</b><span>URLs tested</span></div><div class="summary-item"><b>__VIEWPORTS__</b><span>Viewports</span></div><div class="summary-item"><b>__COVERFAILS__</b><span>HTTP failures</span></div></div>
<div class="matrix" id="matrix"></div></div>
</section>

<section id="evidence" class="tab" hidden>
<div class="panel"><div class="section-title">Visual evidence gallery</div>
<p class="sub">Failure screenshots are marked in red. Finding screenshots are captured with Chromium using GET-only requests and are linked directly to the originating finding.</p>
<div id="gallery" class="gallery"></div></div>
<div class="panel"><div class="section-title">Security evidence capture log</div><div class="matrix" id="securityEvidence"></div></div>
</section>

<section id="execution" class="tab" hidden>
<div class="panel"><div class="section-title">Execution metadata</div><pre id="meta"></pre></div>
</section>

<footer>Sentinel Assessment Framework • Automated observations require appropriate validation.</footer>
</div>

<script>
const findings=__FINDINGS__;
const meta=__META__;
const coverage=__COVERAGE__;
const gallery=__GALLERY__;
const securityEvidence=__SECURITY__;
const colors=__COLORS__;
const esc=function(v){return String(v==null?"":v).replace(/[&<>"']/g,function(c){return {"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]})};
const tabs=document.querySelectorAll(".nav button");
tabs.forEach(function(b){b.addEventListener("click",function(){tabs.forEach(function(x){x.classList.remove("active")});b.classList.add("active");document.querySelectorAll(".tab").forEach(function(x){x.hidden=x.id!==b.dataset.tab})})});
const cat=document.getElementById("cat");
Object.keys(__CATEGORY_JSON__).sort().forEach(function(c){const o=document.createElement("option");o.value=c;o.textContent=c;cat.appendChild(o)});
function renderFindings(){
 const q=document.getElementById("search").value.toLowerCase(), s=document.getElementById("sev").value, c=cat.value, list=document.getElementById("list");
 const filtered=findings.filter(function(f){const hay=JSON.stringify(f).toLowerCase();return (!q||hay.includes(q))&&(!s||f.severity===s)&&(!c||f.category===c)});
 if(!filtered.length){list.innerHTML='<div class="empty">No matching findings.</div>';return}
 list.innerHTML=filtered.map(function(f){
  const color=colors[f.severity]||colors.Info;
  const shots=f.screenshots_relative||[];
  const shotHtml=shots.length?'<div style="margin-top:12px"><b>Visual evidence ('+shots.length+'):</b><div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:8px;margin-top:8px">'+shots.map(function(p){return '<a href="'+esc(p)+'" target="_blank" rel="noopener"><img src="'+esc(p)+'" alt="Security evidence screenshot" style="width:100%;border:1px solid #263b55;border-radius:10px"></a>'}).join("")+'</div></div>': '<p class="warn"><b>No screenshot captured for this finding.</b></p>';
  return '<article class="finding"><div class="fh"><span class="badge" style="background:'+color+'">'+esc(f.severity)+'</span><span class="fid">'+esc(f.id)+'</span><span class="fid">'+esc(f.confidence)+' confidence</span><span class="fid">'+esc(f.method||"GET")+'</span></div><h3>'+esc(f.title)+'</h3><div class="url">'+esc(f.url)+'</div><details open><summary>Evidence / impact / remediation</summary><p><b>Category:</b> '+esc(f.category)+' &nbsp; <b>OWASP:</b> '+esc(f.owasp||"-")+' &nbsp; <b>Parameter:</b> '+esc(f.parameter||"-")+'</p><pre>'+esc(f.evidence)+'</pre>'+shotHtml+'<p><b>Impact:</b> '+esc(f.impact)+'</p><p><b>Remediation:</b> '+esc(f.remediation)+'</p></details></article>'
 }).join("");
}
["search","sev"].forEach(function(id){document.getElementById(id).addEventListener("input",renderFindings)});
cat.addEventListener("change",renderFindings);renderFindings();

const rows=coverage.results||[];
document.getElementById("matrix").innerHTML=rows.length?'<table><thead><tr><th>Browser</th><th>Viewport</th><th>URL</th><th>Status</th><th>Load</th><th>Console</th><th>Network</th><th>Overflow</th><th>Evidence</th></tr></thead><tbody>'+rows.map(function(r){return '<tr><td>'+esc(r.browser)+'</td><td>'+esc(r.viewport)+'</td><td>'+esc(r.url)+'</td><td class="'+((r.status||0)>=400?"fail":"ok")+'">'+esc(r.status||"-")+'</td><td>'+esc(r.load_ms||0)+' ms</td><td>'+r.console_errors.length+'</td><td>'+r.request_failures.length+'</td><td>'+((r.horizontal_overflow)?"YES":"NO")+'</td><td>'+(r.screenshot?'<a href="../'+esc(String(r.screenshot).replace(/\\/g,"/"))+'" target="_blank">open</a>':"-")+'</td></tr>'}).join("")+'</tbody></table>':'<div class="empty">No Chrome coverage metadata recorded.</div>';

document.getElementById("gallery").innerHTML=gallery.length?gallery.map(function(g){return '<article class="shot '+(g.kind==="failure"?"failure":"")+'"><span class="tag '+(g.kind==="failure"?"failure":"")+'">'+esc(g.kind.toUpperCase())+'</span><a href="'+esc(g.path)+'" target="_blank" rel="noopener"><img src="'+esc(g.path)+'" alt="'+esc(g.name)+'"></a><div class="caption">'+esc(g.name)+'<br>'+esc(Math.round((g.size||0)/1024))+' KB</div></article>'}).join(""):'<div class="empty">No screenshots were generated.</div>';

document.getElementById("securityEvidence").innerHTML=securityEvidence.length?'<table><thead><tr><th>Finding</th><th>URL</th><th>Status</th><th>Console errors</th><th>Screenshot</th><th>Error</th></tr></thead><tbody>'+securityEvidence.map(function(x){return '<tr><td>'+esc(x.finding_id)+'</td><td>'+esc(x.url)+'</td><td>'+esc(x.status||"-")+'</td><td>'+((x.console_errors||[]).length)+'</td><td>'+(x.screenshot?'<a href="../'+esc(String(x.screenshot).replace(/\\/g,"/"))+'" target="_blank">open</a>':"-")+'</td><td>'+esc(x.error||"-")+'</td></tr>'}).join("")+'</tbody></table>':'<div class="empty">No security browser captures were required.</div>';

document.getElementById("meta").textContent=JSON.stringify(meta,null,2);
</script>
</body>
</html>''';

    replacements = {
        "__TARGET__": html.escape(report["target"]),
        "__GENERATED__": html.escape(report["generated_at"]),
        "__SCHEMA__": html.escape(report["schema_version"]),
        "__PROFILE__": html.escape(str(report["metadata"].get("profile", "-"))),
        "__CARDS__": "".join(cards),
        "__TOTAL__": str(report["total_findings"]),
        "__CATEGORIES__": str(len(report["category_summary"])),
        "__HIGHCONF__": str(report["confidence_summary"].get("High", 0)),
        "__CHECKS__": str(browser["checks"]),
        "__CATEGORIES_HTML__": "".join(category_cards) or '<div class="empty">No findings.</div>',
        "__SCREENSHOTS__": str(len(report["evidence_gallery"])),
        "__FAILSCREENS__": str(failed_screens),
        "__MARKED__": str(browser["marked"]),
        "__SECURITYCAPS__": str(len(report.get("security_evidence", []))),
        "__URLS__": str(browser["urls"]),
        "__VIEWPORTS__": str(browser["viewports"]),
        "__COVERFAILS__": str(browser["failures"]),
        "__FINDINGS__": findings_json,
        "__META__": meta_json,
        "__COVERAGE__": coverage_json,
        "__GALLERY__": gallery_json,
        "__SECURITY__": security_json,
        "__COLORS__": json.dumps(SEVERITY_COLOR),
        "__CATEGORY_JSON__": json.dumps(report["category_summary"]),
    }
    for key, value in replacements.items():
        template = template.replace(key, value)
    return template
