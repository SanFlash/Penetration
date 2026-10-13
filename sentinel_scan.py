#!/usr/bin/env python3
"""Sentinel Core Engine CLI: bounded, evidence-backed, authorized web assessment."""
from __future__ import annotations
import argparse
import html
import json
import os
import sys
import zipfile
from pathlib import Path
import config
from scanners.engine_core import AssessmentEngine, AssessmentPolicy, SafeTransport
from scanners.core_checks import register_core_checks
from utils.scope import OutOfScopeError, canonical_origin


def _write_html(report, destination):
    rows = []
    for f in report.get("findings", []):
        cells = [f.get("severity", "Info"), f.get("title", "Untitled"),
                 f.get("category", ""), f.get("url", ""), f.get("detail", ""),
                 f.get("remediation", "")]
        rows.append("<tr>" + "".join("<td>{}</td>".format(html.escape(str(c))) for c in cells) + "</tr>")
    summary = report.get("summary", {})
    phases = []
    for phase in report.get("phase_status", []):
        errors = "; ".join(phase.get("errors", []))
        phases.append("<tr>{}</tr>".format("".join(
            "<td>{}</td>".format(html.escape(str(c))) for c in (
                phase.get("name", ""), phase.get("status", ""), phase.get("checks", 0),
                str(phase.get("duration_ms", 0)) + " ms", errors)
        )))
    limitations = "".join("<li>{}</li>".format(html.escape(str(x))) for x in report.get("limitations", []))
    document = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Sentinel Core Security Assessment</title>
<style>
:root{color-scheme:dark;font-family:system-ui,sans-serif;background:#0b1020;color:#e8eefb}
body{margin:0;padding:24px;max-width:1500px;margin-inline:auto}header,.panel{background:#141d32;border:1px solid #2c3a55;border-radius:14px;padding:20px;margin-bottom:18px}
h1{font-size:clamp(1.5rem,3vw,2.3rem)}.muted{color:#aab8d0}.metrics{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:12px}
.metric{padding:14px;background:#0d1527;border-radius:10px}.metric b{display:block;font-size:1.7rem}
.table-wrap{overflow-x:auto}table{width:100%;border-collapse:collapse;min-width:850px}th,td{text-align:left;vertical-align:top;padding:12px;border-bottom:1px solid #2c3a55;overflow-wrap:anywhere}
th{background:#141d32}.footer{color:#aab8d0;font-size:.9rem}@media(max-width:700px){body{padding:10px}}
</style></head><body>
<header><h1>Sentinel Core Security Assessment</h1><p class="muted">Author: Satyendra Kumar Namdeo · Target: {target}</p>
<p>Status: <b>{status}</b> · Completed: {completed}</p></header>
<section class="panel metrics"><div class="metric">Findings<b>{findings}</b></div><div class="metric">Requests<b>{requests}</b></div>
<div class="metric">Checks<b>{checks}</b></div><div class="metric">Duration<b>{duration}s</b></div><div class="metric">High/Critical<b>{urgent}</b></div></section>
<section class="panel"><h2>Findings and remediation</h2><p class="muted">Automated candidates require validation. No finding does not prove a control is secure.</p>
<div class="table-wrap"><table><thead><tr><th>Severity</th><th>Finding</th><th>Category</th><th>URL</th><th>Evidence summary</th><th>Recommended fix</th></tr></thead><tbody>{rows}</tbody></table></div></section>
<section class="panel"><h2>Execution phases</h2><div class="table-wrap"><table><thead><tr><th>Phase</th><th>Status</th><th>Checks</th><th>Duration</th><th>Errors</th></tr></thead><tbody>{phases}</tbody></table></div></section>
<section class="panel"><h2>Limitations</h2><ul>{limitations}</ul></section>
<p class="footer">Bounded request summaries and hashes are in the JSON bundle. This is not a certification of security.</p></body></html>""".format(
        target=html.escape(report.get("target_origin", "")),
        status=html.escape(str(summary.get("overall_status", "unknown"))),
        completed=html.escape(report.get("completed_at", "")),
        findings=len(report.get("findings", [])), requests=report.get("request_count", 0),
        checks=report.get("checks_executed", 0), duration=report.get("duration_seconds", 0),
        urgent=summary.get("by_severity", {}).get("critical", 0) + summary.get("by_severity", {}).get("high", 0),
        rows="".join(rows), phases="".join(phases), limitations=limitations,
    )
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(document, encoding="utf-8")


def main(argv=None):
    parser = argparse.ArgumentParser(description="Sentinel Core Engine — authorized, bounded web security assessment")
    parser.add_argument("--target", default=os.getenv("SENTINEL_DEFAULT_TARGET", config.PENTEST_TARGET_ORIGIN))
    parser.add_argument("--confirm-authorized", action="store_true", help="Confirm ownership or written authorization.")
    parser.add_argument("--max-urls", type=int, default=25)
    parser.add_argument("--max-probes", type=int, default=120)
    parser.add_argument("--max-runtime", type=int, default=180)
    parser.add_argument("--rate", type=float, default=2.0, help="Requests per second (0.1–8).")
    parser.add_argument("--out", default=config.REPORT_DIR, help="Output directory.")
    args = parser.parse_args(argv)
    if not args.confirm_authorized:
        parser.error("Security assessment requires --confirm-authorized.")
    try:
        origin = canonical_origin(args.target)
        policy = AssessmentPolicy(target=origin, max_urls=args.max_urls, max_probes=args.max_probes,
                                 max_runtime_seconds=args.max_runtime, rate_per_second=args.rate)
    except (ValueError, OutOfScopeError) as exc:
        parser.error(str(exc))
    out, evidence_dir = Path(args.out), Path(config.EVIDENCE_DIR)
    engine = AssessmentEngine(policy, transport=SafeTransport(policy, evidence_dir=evidence_dir))
    register_core_checks(engine)
    print(f"[SENTINEL] Target: {origin}")
    print(f"[SENTINEL] Budget: {policy.max_probes} requests; {policy.max_urls} pages; {policy.max_runtime_seconds}s; {policy.rate_per_second} req/s")
    report = engine.run()
    json_path = Path(engine.write_json(report, out / "core_report.json"))
    html_path = out / "core_report.html"
    _write_html(report, html_path)
    zip_path = out / "sentinel_core_bundle.zip"
    out.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.write(json_path, arcname="core_report.json")
        archive.write(html_path, arcname="core_report.html")
        evidence = evidence_dir / "engine_evidence.jsonl"
        if evidence.is_file():
            archive.write(evidence, arcname="evidence/engine_evidence.jsonl")
    summary = report["summary"]
    print(f"[SENTINEL] Status: {summary['overall_status']} | findings: {summary['finding_count']} | requests: {report['request_count']}")
    print(f"[REPORT] JSON: {json_path}\n[REPORT] HTML: {html_path}\n[REPORT] ZIP: {zip_path}")
    return 0 if summary["overall_status"] in {"completed", "partial"} else 2


if __name__ == "__main__":
    sys.exit(main())
