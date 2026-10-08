"""Generate interactive JSON and self-contained HTML assessment reports."""
import html
import json
import os
import re
import shutil
import zipfile
from collections import Counter
from datetime import datetime, timezone

from reports.remediation import build_remediation_summary, enrich_finding
from reports.exporter import make_portable_html, make_pdf
from reports.xlsx_exporter import generate_xlsx


SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
SEVERITY_COLOR = {
    "Critical": "#ff4d6d",
    "High": "#ff8a4c",
    "Medium": "#ffc857",
    "Low": "#38e8a0",
    "Info": "#7d93ad",
}




_FRIENDLY_EXPLANATIONS = {
    "missing security response headers": ("The website is not sending one or more browser security protections that help reduce common attack paths.", "An attacker may have an easier time abusing browser behavior or combining another weakness with this missing protection.", "Add the recommended security headers at the application or web-server layer, then retest the affected pages."),
    "cookie missing secure attribute": ("A browser cookie used by the website is not explicitly restricted to secure HTTPS connections.", "If an insecure connection is ever available, the cookie could be exposed in transit.", "Mark sensitive cookies as Secure and verify that the entire login/session flow remains HTTPS-only."),
    "cookie missing httponly attribute": ("A browser cookie can potentially be read by client-side scripts.", "If malicious script code reaches the page, it may be able to access the cookie and misuse the session.", "Use HttpOnly for sensitive session cookies unless the application has a documented need for JavaScript access."),
    "cookie missing samesite attribute": ("A browser cookie does not clearly define how it should behave when requests originate from another website.", "This can weaken browser-level protection around cross-site requests.", "Set an explicit SameSite policy appropriate to the application's login and cross-site workflows."),
    "directory listing appears enabled": ("The server appears to show a browsable list of files or folders that should normally remain hidden.", "Visitors may discover files, backups, logs or other resources that reveal useful information about the application.", "Disable directory browsing and confirm that only intended public files can be requested."),
    "verbose diagnostic information exposed": ("The website is revealing internal diagnostic information in a response that is visible to visitors.", "This information can give an attacker useful clues about the application's internal technology and failure paths.", "Show a generic public error message and keep detailed diagnostic information in server-side logs."),
    "potentially sensitive resource accessible": ("A resource that normally should not be publicly reachable can be opened without the expected protection.", "It may expose configuration, source-control information, environment details or other internal information.", "Remove the resource from the public deployment or protect it with appropriate server-side access controls."),
}

def _friendly_fields(item: dict) -> dict:
    title = str(item.get("title", "")).strip().lower()
    for key, values in _FRIENDLY_EXPLANATIONS.items():
        if key in title:
            return {"plain_language_summary": values[0], "why_it_matters": values[1], "recommended_action": values[2]}
    return {"plain_language_summary": f"The assessment found a condition that may weaken the website's security: {item.get('title', 'Security issue')}.", "why_it_matters": str(item.get("impact") or "The condition should be reviewed because it may increase the application's exposure to misuse."), "recommended_action": str(item.get("remediation") or "Review the affected page or component and apply the appropriate security control.")}

def _normalize_finding(finding: dict) -> dict:
    item = enrich_finding(finding)
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
    item.update(_friendly_fields(item))
    return item


def _finding_location(item: dict) -> dict:
    """Build explicit, non-speculative location metadata for every finding."""
    url = str(item.get("url") or "").strip()
    method = str(item.get("method") or "GET").upper()
    parameter = str(item.get("parameter") or "").strip()
    selector = str(item.get("selector") or item.get("element") or "").strip()
    return {
        "url": url,
        "method": method,
        "parameter": parameter or None,
        "element": selector or None,
        "location": url or "Target origin",
    }


def _compatibility_meta(metadata: dict) -> dict:
    return (
        metadata.get("ui_responsive")
        or metadata.get("compatibility")
        or {}
    )


def _safe_relative_path(path: str, out_dir: str) -> str | None:
    """Return a report-local URL for an evidence file.
    
    Reports are served from /reports and evidence is bundled into
    /reports/evidence so links never need parent-directory traversal.
    """
    if not path:
        return None
    path = os.path.normpath(str(path))
    out_dir_abs = os.path.abspath(out_dir)
    bundle_dir = os.path.abspath(os.path.join(out_dir_abs, "evidence"))
    path_abs = os.path.abspath(path)

    try:
        if os.path.commonpath([path_abs, bundle_dir]) == bundle_dir:
            return os.path.relpath(path_abs, out_dir_abs).replace("\\", "/")
    except ValueError:
        pass

    if not os.path.exists(path_abs):
        return None

    try:
        rel = os.path.relpath(path_abs, out_dir_abs)
    except ValueError:
        return None

    # Never emit ../ links from the hosted report.
    if rel == ".." or rel.startswith(".." + os.sep):
        return None
    return rel.replace("\\", "/")


def _bundle_evidence_path(path: str, evidence_dir: str, out_dir: str) -> str | None:
    if not path:
        return None
    try:
        rel = os.path.relpath(os.path.abspath(str(path)), os.path.abspath(evidence_dir))
    except ValueError:
        return None
    if rel == '..' or rel.startswith('..' + os.sep):
        return None
    bundled = os.path.join(out_dir, 'evidence', rel)
    return _safe_relative_path(bundled, out_dir) if os.path.isfile(bundled) else None


def _collect_gallery(evidence_dir: str, out_dir: str, findings: list[dict]) -> list[dict]:
    gallery = []
    if os.path.isdir(evidence_dir):
        for root, _, files in os.walk(evidence_dir):
            for name in sorted(files):
                if not name.lower().endswith((".png", ".jpg", ".jpeg", ".webp")):
                    continue
                path = os.path.join(root, name)
                rel = _bundle_evidence_path(path, evidence_dir, out_dir)
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
        rel = _bundle_evidence_path(screenshot, evidence_dir, out_dir) if screenshot else None
        if rel and rel not in known:
            gallery.append({
                "name": os.path.basename(str(screenshot)),
                "path": rel,
                "kind": "failure" if "failure" in str(screenshot).lower() else "finding",
                "size": os.path.getsize(screenshot) if os.path.exists(screenshot) else 0,
            })
            known.add(rel)
    return gallery


def _is_security_finding(item: dict) -> bool:
    category = str(item.get("category", "")).strip().lower()
    return category not in {"compatibility", "responsive ui", "accessibility"} and not str(item.get("id", "")).startswith("COMP-")


def _security_fingerprint(item: dict) -> tuple:
    title = str(item.get("title", "")).strip().lower()
    category = str(item.get("category", "")).strip().lower()
    method = str(item.get("method", "GET")).upper()
    parameter = str(item.get("parameter") or "").strip().lower()
    evidence = str(item.get("evidence", ""))
    discriminator = ""
    if title == "missing security response headers":
        match = re.search(r"missing:\s*(.+)", evidence, re.I)
        discriminator = ",".join(sorted(x.strip().lower() for x in match.group(1).split(","))) if match else ""
    elif "technology fingerprint disclosed" in title:
        names = []
        if re.search(r"\bServer=", evidence):
            names.append("server")
        if re.search(r"\bX-Powered-By=", evidence, re.I):
            names.append("x-powered-by")
        discriminator = ",".join(names)
    elif "cookie" in title:
        discriminator = str(item.get("cookie_name") or "").lower()
    elif "host-header" in title or "url override" in title:
        match = re.search(r"(?:header|via)\s*=\s*([^;]+)", evidence, re.I)
        discriminator = match.group(1).strip().lower() if match else ""
    elif "source map" in title or "javascript" in title or "api specification" in title:
        discriminator = ""
    else:
        labels = re.findall(r"([A-Za-z][A-Za-z0-9_-]*)\s*=", evidence)
        discriminator = ",".join(sorted(set(x.lower() for x in labels if x.lower() not in {
            "http", "length", "status", "baseline", "mutated", "content_length"
        })))
    return (title, category, method, parameter, discriminator, item.get("severity", "Info"))


def _merge_security_observations(grouped: dict, item: dict) -> None:
    key = _security_fingerprint(item)
    if key not in grouped:
        first = dict(item)
        first["occurrences"] = 1
        first["affected_urls"] = [item.get("url")] if item.get("url") else []
        first["observation_ids"] = [item.get("id")] if item.get("id") else []
        first["screenshots"] = [item["screenshot"]] if item.get("screenshot") else []
        grouped[key] = first
        return
    current = grouped[key]
    current["occurrences"] = current.get("occurrences", 1) + 1
    url = item.get("url")
    if url and url not in current["affected_urls"]:
        current["affected_urls"].append(url)
    fid = item.get("id")
    if fid and fid not in current["observation_ids"]:
        current["observation_ids"].append(fid)
    screenshot = item.get("screenshot")
    if screenshot and screenshot not in current["screenshots"]:
        current["screenshots"].append(screenshot)


def generate(target: str, findings: list, evidence_dir: str, out_dir: str = "reports", metadata: dict | None = None) -> dict:
    os.makedirs(out_dir, exist_ok=True)

    # Bundle evidence beside report.html so hosted links remain valid and the
    # report can be moved/copied without losing its screenshots.
    report_evidence_dir = os.path.join(out_dir, "evidence")
    if os.path.isdir(evidence_dir):
        os.makedirs(report_evidence_dir, exist_ok=True)
        shutil.copytree(evidence_dir, report_evidence_dir, dirs_exist_ok=True)

    raw_count = len(findings)
    normalized = [_normalize_finding(f) for f in findings]


    grouped = {}
    security_grouped = {}
    for item in normalized:
        if _is_security_finding(item):
            _merge_security_observations(security_grouped, item)
            continue
        fid = str(item.get("id", ""))
        base_url = str(item.get("url", "")).split("?", 1)[0] if fid.startswith("COMP-") else str(item.get("url", ""))
        evidence = str(item.get("evidence", ""))
        if fid.startswith("COMP-") and ": " in evidence:
            evidence = evidence.split(": ", 1)[1]
        key = (item.get("title"), item.get("category"), base_url, item.get("parameter"), evidence)
        if key not in grouped:
            first = dict(item)
            first["occurrences"] = 1
            first["screenshots"] = []
            if item.get("screenshot"):
                first["screenshots"].append(item["screenshot"])
            first["viewports"] = []
            first_evidence = str(item.get("evidence", ""))
            if "/" in first_evidence and ":" in first_evidence:
                first["viewports"].append(first_evidence.split(":", 1)[0])
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

    normalized = list(grouped.values()) + list(security_grouped.values())
    for item in normalized:
        if item.get("screenshots"):
            item["screenshot"] = item["screenshots"][0]
        item["screenshots"] = list(dict.fromkeys(item.get("screenshots", [])))
        item["screenshots_relative"] = [
            rel for rel in (
                _bundle_evidence_path(path, evidence_dir, out_dir) for path in item["screenshots"]
            ) if rel
        ]
        item["affected_urls"] = list(dict.fromkeys(item.get("affected_urls", []) or ([item["url"]] if item.get("url") else [])))
        item["location"] = _finding_location(item)
        item["observation_count"] = item.get("occurrences", 1)
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
    for item in security_evidence:
        item["screenshot_relative"] = (
            _bundle_evidence_path(item.get("screenshot"), evidence_dir, out_dir)
            if item.get("screenshot") else None
        )

    coverage_results = []
    for row in browser_results:
        copy = dict(row)
        copy["screenshot_relative"] = (
            _bundle_evidence_path(copy.get("screenshot"), evidence_dir, out_dir)
            if copy.get("screenshot") else None
        )
        coverage_results.append(copy)

    target_overview = dict(meta.get("target_overview") or {})
    target_overview["screenshot_relative"] = (
        _bundle_evidence_path(target_overview.get("screenshot"), evidence_dir, out_dir)
        if target_overview.get("screenshot") else None
    )
    meta["target_overview"] = target_overview

    gallery = _collect_gallery(evidence_dir, out_dir, findings_sorted)
    remediation = build_remediation_summary(findings_sorted)

    for finding in findings_sorted:
        # Every finding screenshot is bundled under report/evidence. Never
        # calculate the public URL directly from the original evidence path,
        # because that path lives outside the report directory on Render.
        finding["screenshot_relative"] = (
            _bundle_evidence_path(finding.get("screenshot"), evidence_dir, out_dir)
            if finding.get("screenshot") else None
        )
        finding["screenshots_relative"] = [
            rel for rel in (
                _bundle_evidence_path(path, evidence_dir, out_dir)
                for path in finding.get("screenshots", [])
            ) if rel
        ]

    evidence_paths = []
    for finding in findings_sorted:
        evidence_paths.extend(finding.get("screenshots_relative") or [])
    evidence_paths.extend(
        item.get("screenshot_relative")
        for item in security_evidence
        if item.get("screenshot_relative")
    )
    evidence_paths.extend(
        row.get("screenshot_relative")
        for row in coverage_results
        if row.get("screenshot_relative")
    )
    if target_overview.get("screenshot_relative"):
        evidence_paths.append(target_overview["screenshot_relative"])

    unique_evidence_paths = list(dict.fromkeys(p for p in evidence_paths if p))
    missing_evidence = [
        p for p in unique_evidence_paths
        if not os.path.isfile(os.path.join(out_dir, p.replace("/", os.sep)))
    ]

    report = {
        "schema_version": "3.0",
        "target": target,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "raw_findings": raw_count,
        "unique_findings": len(findings_sorted),
        "total_observations": sum(int(f.get("observation_count", 1)) for f in findings_sorted),
        "affected_urls": len({
            str(url)
            for finding in findings_sorted
            for url in (finding.get("affected_urls") or [finding.get("url")])
            if url
        }),
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
        "evidence_integrity": {
            "expected_visual_artifacts": len(unique_evidence_paths),
            "resolvable_visual_artifacts": len(unique_evidence_paths) - len(missing_evidence),
            "missing_visual_artifacts": missing_evidence,
            "all_links_report_local": all(not p.startswith("../") and not p.startswith("..\\") for p in unique_evidence_paths),
            "artifact_base_url": "/reports/evidence/",
            "artifact_resolution": "report-local",
            "download_bundle": "sentinel_full_report_bundle.zip",
        },
        "remediation": remediation,
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

    # HTML/JSON are the canonical report. Optional exports must never be
    # allowed to make the assessment appear stuck or erase the usable report.
    portable_html_path = None
    pdf_path = None
    xlsx_path = None
    export_errors = {}

    try:
        portable_html_path = make_portable_html(
            html_path,
            os.path.join(out_dir, "report_portable.html"),
        )
    except Exception as exc:
        export_errors["portable_html"] = f"{type(exc).__name__}: {exc}"

    if portable_html_path:
        try:
            pdf_path = make_pdf(
                portable_html_path,
                os.path.join(out_dir, "report.pdf"),
            )
        except Exception as exc:
            export_errors["pdf"] = f"{type(exc).__name__}: {exc}"

    try:
        xlsx_path = generate_xlsx(
            report,
            os.path.join(out_dir, "penetration_report.xlsx"),
        )
    except Exception as exc:
        export_errors["xlsx"] = f"{type(exc).__name__}: {exc}"
    report["exports"] = {
        "html_path": html_path,
        "portable_html_path": portable_html_path,
        "pdf_path": pdf_path,
        "xlsx_path": xlsx_path,
        "portable": bool(portable_html_path),
        "pdf_generated": bool(pdf_path),
        "xlsx_generated": bool(xlsx_path),
        "errors": export_errors,
    }

    # Complete offline package: HTML/PDF/XLSX/JSON/manifest plus every
    # report-local evidence artifact.
    bundle_path = os.path.join(out_dir, "sentinel_full_report_bundle.zip")
    bundle_error = None
    try:
        with zipfile.ZipFile(bundle_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for candidate in (html_path, portable_html_path, pdf_path, xlsx_path, json_path, manifest_path):
                if candidate and os.path.isfile(candidate):
                    archive.write(candidate, os.path.basename(candidate))
            bundled_evidence = os.path.join(out_dir, "evidence")
            if os.path.isdir(bundled_evidence):
                for root, _, names in os.walk(bundled_evidence):
                    for name in names:
                        path = os.path.join(root, name)
                        archive.write(path, os.path.relpath(path, out_dir))
    except Exception as exc:
        bundle_error = f"{type(exc).__name__}: {exc}"
    report["exports"]["bundle_path"] = bundle_path if os.path.isfile(bundle_path) else None
    report["exports"]["bundle_generated"] = os.path.isfile(bundle_path)
    if bundle_error:
        report["exports"]["bundle_error"] = bundle_error

    # Persist the final export inventory into findings.json.
    with open(json_path, "w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2, ensure_ascii=False)

    return {
        "json_path": json_path,
        "html_path": html_path,
        "portable_html_path": portable_html_path,
        "pdf_path": pdf_path,
        "xlsx_path": xlsx_path,
        "manifest_path": manifest_path,
        "report": report,
    }


def _render_html(report: dict) -> str:
    findings_json = json.dumps(report["findings"], ensure_ascii=False).replace("</", "<\\/")
    gallery_json = json.dumps(report["evidence_gallery"], ensure_ascii=False).replace("</", "<\\/")
    coverage_json = json.dumps(report["metadata"].get("ui_responsive") or report["metadata"].get("compatibility") or {}, ensure_ascii=False).replace("</", "<\\/")
    security_json = json.dumps(report.get("security_evidence", []), ensure_ascii=False).replace("</", "<\\/")
    meta_json = json.dumps(report.get("metadata", {}), ensure_ascii=False).replace("</", "<\\/")

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
    attack = report.get("metadata", {}).get("attack_surface") or {}
    attack_summary = attack.get("summary") or {}
    attack_rows = attack.get("routes") or []
    attack_cells = [
        ("Unique routes", attack_summary.get("total", 0)),
        ("API-like", attack_summary.get("api_like", 0)),
        ("Documented", attack_summary.get("documented", 0)),
        ("Observed", attack_summary.get("observed", 0)),
        ("State-changing candidates", attack_summary.get("state_changing_candidates", 0)),
    ]
    attack_cards = "".join('<div class="summary-item"><b>%s</b><span>%s</span></div>' % (v, html.escape(k)) for k, v in attack_cells)
    attack_table_rows = []
    for row in attack_rows[:40]:
        flags = []
        if row.get("api_like"): flags.append("API")
        if row.get("documented"): flags.append("Documented")
        if row.get("state_changing_candidate"): flags.append("State-changing candidate")
        attack_table_rows.append("<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>" % (
            html.escape(str(row.get("method", "GET"))),
            html.escape(str(row.get("path", row.get("url", "")))),
            html.escape(", ".join(row.get("sources") or [])),
            html.escape(", ".join(flags) or "-"),
            html.escape(str(row.get("evidence") or ""))[:220],
        ))
    attack_html = '<div class="summary-strip">%s</div>' % attack_cards
    if attack_table_rows:
        attack_html += '<div style="overflow:auto;margin-top:14px"><table><thead><tr><th>Method</th><th>Path</th><th>Sources</th><th>Classification</th><th>Evidence</th></tr></thead><tbody>%s</tbody></table></div>' % "".join(attack_table_rows)
    else:
        attack_html += '<div class="empty" style="margin-top:14px">No correlated attack-surface inventory was recorded for this run.</div>'
    failed_screens = sum(1 for x in report["evidence_gallery"] if x["kind"] == "failure")

    # Render core evidence directly into HTML as a fallback. This keeps the
    # Evidence tab useful even if optional report JavaScript fails.
    def _report_artifact_url(path):
        raw = str(path or "").replace("\\", "/")
        if raw.startswith("evidence/"):
            raw = raw[len("evidence/"):]
        raw = raw.lstrip("/")
        return "/reports/evidence/" + raw if raw and ".." not in raw.split("/") else ""

    gallery_html = []
    for item in report.get("evidence_gallery", []):
        src = _report_artifact_url(item.get("path"))
        if not src:
            continue
        kind = html.escape(str(item.get("kind", "evidence")).upper())
        name = html.escape(str(item.get("name", os.path.basename(str(item.get("path", ""))))))
        size = round((item.get("size") or 0) / 1024)
        failure = "failure" if item.get("kind") == "failure" else ""
        gallery_html.append(
            '<article class="shot %s"><span class="tag %s">%s</span>'
            '<a href="%s" target="_blank" rel="noopener noreferrer"><img src="%s" alt="%s" loading="lazy"></a>'
            '<div class="caption">%s<br>%s KB · <a href="%s" target="_blank" rel="noopener noreferrer">Open evidence</a></div></article>'
            % (failure, failure, kind, html.escape(src, quote=True), html.escape(src, quote=True),
               name, name, size, html.escape(src, quote=True))
        )
    gallery_html_text = "".join(gallery_html) or '<div class="empty">No visual artifacts were bundled into this report.</div>'

    server_finding_cards = []
    for finding in findings_sorted:
        sev = html.escape(str(finding.get("severity", "Info")))
        color = SEVERITY_COLOR.get(str(finding.get("severity", "Info")), SEVERITY_COLOR["Info"])
        shots = finding.get("screenshots_relative") or []
        shot_html = "".join(evidenceAnchor(p, "Finding evidence") for p in shots) if shots else '<div class="warn">No visual screenshot was required or successfully captured. Structured evidence is shown above.</div>'
        server_finding_cards.append(
            '<article class="finding"><div class="fh"><span class="badge" style="background:%s">%s</span><span class="fid">%s</span><span class="fid">%s confidence</span><span class="fid">%s</span></div>'
            '<h3>%s</h3>'
            '<div class="finding-grid"><div><b>WHERE FOUND</b><div class="url">%s</div></div><div><b>METHOD</b><div>%s</div></div><div><b>PARAMETER / ELEMENT</b><div>%s</div></div><div><b>CATEGORY / CWE / OWASP</b><div>%s / %s / %s</div></div></div>'
            '<div class="finding-section"><b>WHAT IS THE ISSUE?</b><p>%s</p></div>'
            '<div class="finding-section"><b>OBSERVED EVIDENCE</b><pre>%s</pre></div>'
            '<div class="finding-section"><b>IMPACT</b><p>%s</p></div>'
            '<div class="finding-section"><b>HOW TO FIX</b><p>%s</p><p><b>Validation:</b> %s</p></div>'
            '<div class="finding-section"><b>VISUAL EVIDENCE</b><div class="finding-evidence-grid">%s</div></div></article>' % (
                color, sev, html.escape(str(finding.get("id",""))), html.escape(str(finding.get("confidence","Medium"))),
                html.escape(str(finding.get("observation_count",1))), html.escape(str(finding.get("title","Untitled finding"))),
                html.escape(str(finding.get("url") or "Target origin")), html.escape(str(finding.get("method","GET"))),
                html.escape(str(finding.get("parameter") or finding.get("element") or "-")),
                html.escape(str(finding.get("category") or "-")), html.escape(str(finding.get("cwe") or "-")), html.escape(str(finding.get("owasp") or "-")),
                html.escape(str(finding.get("plain_language_summary") or finding.get("detail") or "-")),
                html.escape(str(finding.get("evidence") or finding.get("detail") or "-")),
                html.escape(str(finding.get("impact") or finding.get("why_it_matters") or "-")),
                html.escape(str(finding.get("recommended_action") or finding.get("fix_summary") or finding.get("remediation") or "-")),
                html.escape(str(finding.get("validation_steps") or "-")), shot_html))
    findings_html_text = "".join(server_finding_cards) or '<div class="empty">No findings were recorded.</div>'

    target_overview_html = '<div class="empty">Target overview was not captured.</div>'
    overview = report.get("metadata", {}).get("target_overview") or {}
    overview_src = _report_artifact_url(overview.get("screenshot_relative"))
    if overview_src:
        target_overview_html = (
            '<div class="shot"><span class="tag">TARGET OVERVIEW</span>'
            '<a href="%s" target="_blank" rel="noopener noreferrer"><img src="%s" alt="Target website overview" loading="lazy"></a>'
            '<div class="caption"><a href="%s" target="_blank" rel="noopener noreferrer">Open target website</a><br>%s · HTTP %s</div></div>'
            % (html.escape(overview_src, quote=True), html.escape(overview_src, quote=True),
               html.escape(str(overview.get("target") or target), quote=True),
               html.escape(str(overview.get("title") or "")),
               html.escape(str(overview.get("status") or "-")))
        )

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
.nav{display:flex;gap:8px;flex-wrap:wrap;margin:14px 0;position:sticky;top:8px;z-index:20;padding:4px;background:#050810ee;backdrop-filter:blur(10px);border:1px solid var(--line);border-radius:12px}.nav a{display:inline-flex;align-items:center;justify-content:center;background:#08111d;color:#a9bdd1;border:1px solid var(--line);border-radius:9px;padding:9px 12px;text-decoration:none;font-weight:700;cursor:pointer;min-height:40px}.nav a:hover,.nav a:focus-visible{color:#06110d;background:var(--accent);border-color:var(--accent);outline:2px solid #38e8a055;outline-offset:2px}.tab{display:none}.tab#overview{display:block}.tab:target{display:block}.shell:has(.tab:target) #overview{display:none}
.panel{background:#09111ddd;border:1px solid var(--line);border-radius:16px;padding:16px;box-shadow:0 14px 50px #0005;margin-bottom:14px}.section-title{font-size:12px;color:#9bb0c6;letter-spacing:.12em;text-transform:uppercase;margin:0 0 13px}
.grid{display:grid;grid-template-columns:1.25fr .75fr;gap:14px}.riskgrid{display:grid;grid-template-columns:repeat(5,1fr);gap:9px}.risk-card{position:relative;background:var(--panel2);border:1px solid var(--line);border-radius:12px;padding:13px;overflow:hidden}.risk-card span{position:absolute;left:0;top:0;width:4px;height:100%;background:var(--c)}.risk-card small{display:block;color:var(--muted)}.risk-card b{font-size:26px}
.kpis{display:grid;grid-template-columns:repeat(3,1fr);gap:9px}.kpi{padding:14px;background:var(--panel2);border:1px solid var(--line);border-radius:12px}.kpi b{display:block;font-size:25px}.kpi span{color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.08em}
.cat{padding:9px 0;border-bottom:1px solid #162438}.cat>div:first-child{display:flex;justify-content:space-between;gap:10px}.cat span{color:var(--muted)}.catbar{height:7px;background:#132033;border-radius:99px;overflow:hidden;margin-top:7px}.catbar i{display:block;height:100%;background:linear-gradient(90deg,var(--blue),var(--accent))}
.controls{display:flex;gap:9px;flex-wrap:wrap;margin-bottom:12px}input,select{background:#07101b;color:var(--text);border:1px solid var(--line);border-radius:9px;padding:9px 10px;min-height:40px}input{flex:1;min-width:220px}
.finding-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin:12px 0}.finding-grid>div{border:1px solid var(--line);border-radius:10px;padding:10px;background:#07111d}.finding-grid b,.finding-section>b{font-size:10px;letter-spacing:.08em;color:var(--muted)}.finding-section{margin-top:12px;padding:12px;border:1px solid var(--line);border-radius:10px;background:#07111d}.finding-section pre{margin:8px 0;max-height:280px;overflow:auto}.finding-evidence-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:10px;margin-top:10px}
.finding{border:1px solid var(--line);border-radius:13px;background:#08101b;padding:15px;margin:10px 0}.fh{display:flex;gap:8px;align-items:center;flex-wrap:wrap}.badge{border-radius:999px;padding:4px 8px;color:#06110d;font-weight:800;font-size:11px}.fid{color:var(--muted);font-family:Consolas,monospace;font-size:11px}.finding h3{margin:9px 0 4px;font-size:16px}.finding .url{color:#8aa1b8;word-break:break-all;font-size:12px}details{margin-top:10px}summary{cursor:pointer;color:#9fc1df}pre{background:#03070d;border:1px solid #142238;border-radius:9px;padding:11px;overflow:auto;white-space:pre-wrap;word-break:break-word;color:#bdd0e3}.empty{padding:35px;text-align:center;color:var(--muted)}
.matrix{overflow:auto}table{width:100%;border-collapse:collapse;min-width:720px}th,td{padding:9px;border-bottom:1px solid #17253a;text-align:left;vertical-align:top}th{color:var(--muted);font-size:11px;text-transform:uppercase}.ok{color:var(--accent)}.fail{color:var(--danger)}.warn{color:var(--warn)}
.gallery{display:grid;grid-template-columns:repeat(3,1fr);gap:12px}.shot{border:1px solid var(--line);background:#07101b;border-radius:12px;padding:9px}.shot img{width:100%;aspect-ratio:16/10;object-fit:cover;border-radius:8px;border:1px solid #1a2a40}.shot .caption{font-size:12px;margin-top:7px;word-break:break-word}.shot.failure{border-color:#6b2436}.shot.failure .caption{color:#ff8da3}.tag{display:inline-block;border-radius:99px;padding:3px 7px;font-size:10px;font-weight:800;background:#142237;color:#a9bdd1;margin-bottom:5px}.tag.failure{background:#45182a;color:#ff9ab0}
.summary-strip{display:grid;grid-template-columns:repeat(4,1fr);gap:9px;margin-top:10px}.summary-item{padding:12px;background:#07101b;border:1px solid var(--line);border-radius:11px}.summary-item b{display:block;font-size:22px}.summary-item span{color:var(--muted);font-size:11px}
footer{color:#62788f;text-align:center;padding:22px;font-size:12px}
@media print{
  body{background:#fff;color:#111}
  .shell{max-width:none;padding:0}
  .nav{display:none!important}
  .tab,.tab[hidden]{display:block!important;visibility:visible!important}
  .tab{break-before:page}
  #overview{break-before:auto}
  .panel{break-inside:avoid;background:#fff;color:#111;border-color:#bbb;box-shadow:none}
  .hero,.finding,.shot,.kpi,.summary-item,.risk-card{box-shadow:none}
  .sub,.chip,.fid,.finding .url,footer{color:#444}
  pre{background:#f5f5f5;color:#111;border-color:#bbb}
  .gallery{grid-template-columns:repeat(2,1fr)}
  a{color:#111;text-decoration:none}
}
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

<nav class="nav" aria-label="Report sections">
<a href="#overview">Overview</a>
<a href="#findings">Findings</a>
<a href="#coverage">Coverage</a>
<a href="#evidence">Evidence</a>
<a href="#remediation">Remediation</a>
<a href="#execution">Execution</a>
</nav>

<section id="overview" class="tab">
<div class="panel"><div class="section-title">Severity distribution</div><div class="riskgrid">__CARDS__</div></div>
<div class="grid">
<div class="panel"><div class="section-title">Assessment metrics</div><div class="kpis">
<div class="kpi"><b>__TOTAL__</b><span>Unique findings</span></div><div class="kpi"><b>__RAW__</b><span>Raw observations</span></div><div class="kpi"><b>__OBS__</b><span>Affected observations</span></div><div class="kpi"><b>__AFFECTED_URLS__</b><span>Affected URLs</span></div>
<div class="kpi"><b>__CATEGORIES__</b><span>Categories</span></div>
<div class="kpi"><b>__HIGHCONF__</b><span>High confidence</span></div>
<div class="kpi"><b>__CHECKS__</b><span>Chrome checks</span></div>
</div></div>
<div class="panel"><div class="section-title">Category distribution</div>__CATEGORIES_HTML__</div>
</div>
<div class="panel"><div class="section-title">Target website overview</div><p class="sub">Chromium opened the authorized target before assessment. This is a viewport overview only; failure evidence remains focused on the responsible DOM element.</p><div id="targetOverview">__TARGET_OVERVIEW_HTML__</div></div>
<div class="panel"><div class="section-title">Assessment health</div><div id="assessmentHealth"></div></div>
<div class="panel"><div class="section-title">Evidence health &amp; downloads</div><p class="sub"><a class="download" href="/reports/sentinel_full_report_bundle.zip">⬇ Download complete report bundle — HTML + PDF + XLSX + JSON + all evidence</a></p><div class="summary-strip">
<div class="summary-item"><b>__SCREENSHOTS__</b><span>Evidence screenshots</span></div>
<div class="summary-item"><b>__FAILSCREENS__</b><span>Failure screenshots</span></div>
<div class="summary-item"><b>__MARKED__</b><span>Marked Chrome checks</span></div>
<div class="summary-item"><b>__SECURITYCAPS__</b><span>Security captures</span></div>
</div></div>
<div class="panel"><div class="section-title">Correlated attack surface</div>__ATTACK_SURFACE__</div>
</section>

<section id="findings" class="tab">
<div class="panel"><div class="section-title">Findings explorer</div>
<div class="controls"><input id="search" placeholder="Search title, URL, category, evidence..."><select id="sev"><option value="">All severities</option><option>Critical</option><option>High</option><option>Medium</option><option>Low</option><option>Info</option></select><select id="cat"><option value="">All categories</option></select></div>
<div id="list">__FINDINGS_HTML__</div></div>
</section>

<section id="coverage" class="tab" hidden>
<div class="panel"><div class="section-title">Chrome / viewport coverage</div>
<div class="summary-strip"><div class="summary-item"><b>__CHECKS__</b><span>Browser checks</span></div><div class="summary-item"><b>__URLS__</b><span>URLs tested</span></div><div class="summary-item"><b>__VIEWPORTS__</b><span>Viewports</span></div><div class="summary-item"><b>__COVERFAILS__</b><span>HTTP failures</span></div></div>
<div class="matrix" id="matrix"></div></div>
</section>

<section id="evidence" class="tab" hidden>
<div class="panel"><div class="section-title">Visual evidence gallery</div>
<p class="sub">Failure screenshots are marked in red. Finding screenshots are captured with Chromium using GET-only requests and are linked directly to the originating finding.</p>
<div id="gallery" class="gallery">__GALLERY_HTML__</div></div>
<div class="panel"><div class="section-title">Security evidence capture log</div><div class="matrix" id="securityEvidence"></div></div>
</section>


<section id="remediation" class="tab" hidden>
<div class="panel"><div class="section-title">Remediation center</div>
<p class="sub">Prioritized corrective actions derived from the observed findings. Impact describes the potential consequence; validation describes how to confirm the fix after deployment.</p>
<div class="summary-strip"><div class="summary-item"><b>__IMMEDIATE__</b><span>Immediate actions</span></div><div class="summary-item"><b>__HIGH__</b><span>High priority</span></div><div class="summary-item"><b>__PLANNED__</b><span>Planned actions</span></div><div class="summary-item"><b>__REVIEW__</b><span>Review actions</span></div></div>
<div id="remediationList"></div></div>
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
const targetOverview=__TARGET_OVERVIEW__;
const remediation=__REMEDIATION__;
const colors=__COLORS__;

// Define escaping before ANY rendering code uses it. A previous ordering bug
// caused a ReferenceError here and prevented all tab/evidence handlers from
// being registered.
const esc=function(v){return String(v==null?"":v).replace(/[&<>"']/g,function(c){return {"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]})};

// All report visuals are intentionally resolved relative to /reports/evidence.
// This avoids parent-directory links and keeps <img> + open links identical.
function artifactUrl(p){
  if(!p) return "";
  const raw=String(p).replace(/\\/g,"/");
  if(raw.startsWith("../") || raw.startsWith("/evidence/") || raw.includes("://")) return "";
  const clean=raw.startsWith("evidence/") ? raw.slice("evidence/".length) : raw.replace(/^\\/+/,"");
  return "/reports/evidence/"+clean;
}
function evidenceAnchor(path, alt){
  const src=artifactUrl(path);
  if(!src) return '<div class="warn"><b>Evidence unavailable:</b> invalid report-local artifact path.</div>';
  return '<a href="'+esc(src)+'" target="_blank" rel="noopener noreferrer"><img src="'+esc(src)+'" alt="'+esc(alt||"Evidence screenshot")+'" style="width:100%;border:1px solid #263b55;border-radius:10px;display:block;min-height:140px;object-fit:contain;background:#03070d" loading="lazy"><span class="caption">Open evidence artifact</span></a>';
}

const phaseStatus=(meta&&meta.phase_status)||{};
const phaseEntries=Object.keys(phaseStatus);
document.getElementById("assessmentHealth").innerHTML=phaseEntries.length
 ? '<div class="matrix"><table><thead><tr><th>Assessment area</th><th>Status</th><th>Duration</th><th>Notes</th></tr></thead><tbody>'+phaseEntries.map(function(k){const p=phaseStatus[k]||{};const failed=p.status==="failed";return '<tr><td>'+esc(k.replace(/_/g," "))+'</td><td class="'+(failed?"fail":"ok")+'">'+esc(p.status||"unknown")+'</td><td>'+esc(p.duration_seconds||"-")+' s</td><td>'+esc(p.error||"Completed")+'</td></tr>'}).join("")+'</tbody></table></div>'
 : '<div class="empty">Assessment phase status will appear as the report is updated.</div>';

const cat=document.getElementById("cat");
Object.keys(__CATEGORY_JSON__).sort().forEach(function(c){const o=document.createElement("option");o.value=c;o.textContent=c;cat.appendChild(o)});
function renderFindings(){
 const q=document.getElementById("search").value.toLowerCase(), s=document.getElementById("sev").value, c=cat.value, list=document.getElementById("list");
 const filtered=findings.filter(function(f){const hay=JSON.stringify(f).toLowerCase();return (!q||hay.includes(q))&&(!s||f.severity===s)&&(!c||f.category===c)});
 if(!filtered.length){list.innerHTML='<div class="empty">No matching findings.</div>';return}
 list.innerHTML=filtered.map(function(f){
  const color=colors[f.severity]||colors.Info;
  const shots=f.screenshots_relative||[];
  const shotHtml=shots.length?'<div style="margin-top:12px"><b>Visual evidence ('+shots.length+'):</b><div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:8px;margin-top:8px">'+shots.map(function(p){return evidenceAnchor(p,"Security evidence screenshot")}).join("")+'</div></div>': '<p class="warn"><b>No screenshot captured for this finding.</b></p>';
  return '<article class="finding"><div class="fh"><span class="badge" style="background:'+color+'">'+esc(f.severity)+'</span><span class="fid">'+esc(f.id)+'</span><span class="fid">'+esc(f.confidence)+' confidence</span><span class="fid">'+esc(f.method||"GET")+'</span><span class="fid">'+esc(f.observation_count||1)+' observation(s)</span></div><h3>'+esc(f.title)+'</h3><div class="url">'+esc(f.url)+(f.affected_urls&&f.affected_urls.length>1?" · affected URLs: "+f.affected_urls.length:"")+'</div><details open><summary>What failed / evidence / how to fix</summary><p><b>What this means:</b> '+esc(f.plain_language_summary)+'</p><p><b>Why it matters:</b> '+esc(f.why_it_matters)+'</p><p><b>Category:</b> '+esc(f.category)+' &nbsp; <b>OWASP:</b> '+esc(f.owasp||"-")+' &nbsp; <b>Parameter:</b> '+esc(f.parameter||"-")+'</p><pre>'+esc(f.evidence)+'</pre>'+shotHtml+'<p><b>Impact:</b> '+esc(f.impact)+'</p><p><b>Recommended action:</b> '+esc(f.recommended_action)+'</p><p><b>Remediation:</b> '+esc(f.remediation)+'</p></details></article>'
 }).join("");
}
["search","sev"].forEach(function(id){document.getElementById(id).addEventListener("input",renderFindings)});
cat.addEventListener("change",renderFindings);renderFindings();

const rows=coverage.results||[];
document.getElementById("matrix").innerHTML=rows.length?'<table><thead><tr><th>Browser</th><th>Viewport</th><th>URL</th><th>Status</th><th>Load</th><th>Console</th><th>Network</th><th>Overflow</th><th>Evidence</th></tr></thead><tbody>'+rows.map(function(r){return '<tr><td>'+esc(r.browser)+'</td><td>'+esc(r.viewport)+'</td><td>'+esc(r.url)+'</td><td class="'+((r.status||0)>=400?"fail":"ok")+'">'+esc(r.status||"-")+'</td><td>'+esc(r.load_ms||0)+' ms</td><td>'+r.console_errors.length+'</td><td>'+r.request_failures.length+'</td><td>'+((r.horizontal_overflow)?"YES":"NO")+'</td><td>'+(r.screenshot_relative?evidenceAnchor(r.screenshot_relative,"Chrome evidence"):"-")+'</td></tr>'}).join("")+'</tbody></table>':'<div class="empty">No Chrome coverage metadata recorded.</div>';

document.getElementById("targetOverview").innerHTML=targetOverview.screenshot_relative
 ? '<div class="shot"><span class="tag">TARGET OVERVIEW</span>'+evidenceAnchor(targetOverview.screenshot_relative,"Target website overview")+'<div class="caption"><a href="'+esc(targetOverview.target||"")+'" target="_blank" rel="noopener">Open target website</a><br>'+esc(targetOverview.title||"")+' · HTTP '+esc(targetOverview.status||"-")+'</div></div>'
 : '<div class="empty">Target overview could not be captured: '+esc(targetOverview.error||"unknown error")+'</div>';

document.getElementById("gallery").innerHTML=gallery.length?gallery.map(function(g){return '<article class="shot '+(g.kind==="failure"?"failure":"")+'"><span class="tag '+(g.kind==="failure"?"failure":"")+'">'+esc(g.kind.toUpperCase())+'</span>'+evidenceAnchor(g.path,g.name)+'<div class="caption">'+esc(g.name)+'<br>'+esc(Math.round((g.size||0)/1024))+' KB</div></article>'}).join(""):'<div class="empty">No screenshots were generated.</div>';

document.getElementById("securityEvidence").innerHTML=securityEvidence.length?'<table><thead><tr><th>Finding</th><th>URL</th><th>Status</th><th>Console errors</th><th>Screenshot</th><th>Failure type</th><th>Exact error</th></tr></thead><tbody>'+securityEvidence.map(function(x){return '<tr><td>'+esc(x.finding_id)+'</td><td>'+esc(x.url)+'</td><td>'+esc(x.status||"-")+'</td><td>'+((x.console_errors||[]).length)+'</td><td>'+(x.screenshot_relative?evidenceAnchor(x.screenshot_relative,"Security evidence"):"-")+'</td><td>'+esc(x.error_type||x.capture?.mode||"-")+'</td><td>'+esc(x.error_description||x.error||x.capture?.focus_reason||"-")+'</td></tr>'}).join("")+'</tbody></table>':'<div class="empty">No security browser captures were required.</div>';


document.getElementById("remediationList").innerHTML=(remediation.actions||[]).length?(remediation.actions||[]).map(function(a){return '<article class="finding"><div class="fh"><span class="badge" style="background:'+((colors[a.severity]||colors.Info))+'">'+esc(a.severity)+'</span><span class="fid">'+esc(a.category)+'</span><span class="fid">'+esc(a.affected_urls)+' affected URL(s)</span></div><h3>'+esc(a.title)+'</h3><p><b>Impact:</b> '+esc(a.impact)+'</p><p><b>How to solve:</b> '+esc(a.fix)+'</p><p><b>How to validate:</b> '+esc(a.validation)+'</p></article>'}).join(""):'<div class="empty">No remediation actions were generated.</div>';

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
        "__TOTAL__": str(report["unique_findings"]),
        "__RAW__": str(report["raw_findings"]),
        "__OBS__": str(report["total_observations"]),
        "__AFFECTED_URLS__": str(report["affected_urls"]),
        "__CATEGORIES__": str(len(report["category_summary"])),
        "__HIGHCONF__": str(report["confidence_summary"].get("High", 0)),
        "__CHECKS__": str(browser["checks"]),
        "__CATEGORIES_HTML__": "".join(category_cards) or '<div class="empty">No findings.</div>',
        "__SCREENSHOTS__": str(len(report["evidence_gallery"])),
        "__FAILSCREENS__": str(failed_screens),
        "__MARKED__": str(browser["marked"]),
        "__SECURITYCAPS__": str(len(report.get("security_evidence", []))),
        "__ATTACK_SURFACE__": attack_html,
        "__URLS__": str(browser["urls"]),
        "__VIEWPORTS__": str(browser["viewports"]),
        "__COVERFAILS__": str(browser["failures"]),
        "__FINDINGS__": findings_json,
        "__META__": meta_json,
        "__COVERAGE__": coverage_json,
        "__GALLERY__": gallery_json,
        "__SECURITY__": security_json,
        "__TARGET_OVERVIEW__": json.dumps(report.get("metadata", {}).get("target_overview") or {}, ensure_ascii=False).replace("</", "<\\/"),
        "__TARGET_OVERVIEW_HTML__": target_overview_html,
        "__FINDINGS_HTML__": findings_html_text,
        "__GALLERY_HTML__": gallery_html_text,
        "__REMEDIATION__": json.dumps(report.get("remediation", {}), ensure_ascii=False).replace("</", "<\\/"),
        "__IMMEDIATE__": str(report.get("remediation", {}).get("priority_counts", {}).get("Immediate", 0)),
        "__HIGH__": str(report.get("remediation", {}).get("priority_counts", {}).get("High", 0)),
        "__PLANNED__": str(report.get("remediation", {}).get("priority_counts", {}).get("Planned", 0)),
        "__REVIEW__": str(report.get("remediation", {}).get("priority_counts", {}).get("Review", 0)),
        "__COLORS__": json.dumps(SEVERITY_COLOR),
        "__CATEGORY_JSON__": json.dumps(report["category_summary"]),
    }
    for key, value in replacements.items():
        template = template.replace(key, value)
    return template
