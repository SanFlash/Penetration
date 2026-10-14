"""Hosted Sentinel web console for Render.

The CLI remains the source of truth for the assessment engine. This module adds
an HTTP control plane so the framework can be run from a browser on Render.
All API routes except /healthz require SENTINEL_ACCESS_TOKEN when configured.
"""
from __future__ import annotations

import html
import json
import os
import threading
import time
from pathlib import Path

from flask import Flask, jsonify, request, send_from_directory

import config
from main import run_pentest_profile
from ui.dashboard import DashboardState
from scanners.coverage_registry import build_coverage_registry

app = Flask(__name__)

ACCESS_TOKEN = os.getenv("SENTINEL_ACCESS_TOKEN", "").strip()
DEFAULT_TARGET = os.getenv("SENTINEL_DEFAULT_TARGET", "").strip() or config.PENTEST_TARGET_ORIGIN

_run_lock = threading.Lock()
_run_thread = None
_state = DashboardState(target=DEFAULT_TARGET, profile="pentest")
_last_result = None
_last_error = None
_run_started_at = None


def _authorized() -> bool:
    if not ACCESS_TOKEN:
        return True
    supplied = request.headers.get("X-Sentinel-Token", "")
    if not supplied:
        supplied = request.args.get("token", "")
    if not supplied:
        supplied = request.cookies.get("sentinel_access_token", "")
    return supplied == ACCESS_TOKEN


def _require_auth():
    if not _authorized():
        return jsonify({"error": "unauthorized", "message": "Provide the configured Sentinel access token."}), 401
    return None


def _worker(target: str, profile: str = "pentest"):
    global _last_result, _last_error
    _last_error = None
    try:
        if profile == "core":
            from sentinel_scan import main as core_main
            def core_progress(event):
                completed = int(event.get("completed", 0))
                total = max(int(event.get("total", 1)), 1)
                _state.update(
                    status="RUNNING",
                    stage="CORE: " + str(event.get("name", "ASSESSMENT")).upper(),
                    detail=f"Phase {completed}/{total} — {event.get('status', 'running')}; requests {event.get('request_count', 0)}; findings {event.get('finding_count', 0)}.",
                    progress=min(95, 5 + int(90 * completed / total)),
                    checks=int(event.get("request_count", 0)),
                    findings=int(event.get("finding_count", 0)),
                    log={"level": "ok" if event.get("status") == "completed" else "warn",
                         "message": f"Core phase {event.get('name')}: {event.get('status')}"},
                )
            rc = core_main([
                "--target", target, "--confirm-authorized",
                "--max-urls", "25", "--max-probes", "120",
                "--max-runtime", "180", "--out", config.REPORT_DIR,
            ], progress_callback=core_progress)
        else:
            rc = run_pentest_profile(
                target,
                headed=False,
                slow_mo=0,
                dashboard=False,
                authorized=True,
                state_override=_state,
            )
        _last_result = {"return_code": rc, "completed_at": time.time()}
        if rc == 0:
            _state.update(
                status="COMPLETE",
                stage="CORE SCAN COMPLETE" if profile == "core" else "PENTEST COMPLETE",
                detail=("Core security report and evidence bundle are ready." if profile == "core" else "Assessment and evidence are ready."),
                progress=100,
            )
        elif profile == "core" and rc == 1:
            _state.update(
                status="PARTIAL",
                stage="CORE SCAN PARTIAL",
                detail="The core scan finished, but one or more phases were incomplete. Review the phase status in the report.",
                progress=100,
            )
        else:
            _state.update(
                status="FAILED",
                stage="ASSESSMENT FAILED",
                detail=f"Assessment exited with return code {rc}.",
            )
    except Exception as exc:
        _last_error = f"{type(exc).__name__}: {exc}"
        _last_result = {"return_code": 1, "completed_at": time.time()}
        _state.update(
            status="FAILED",
            stage="ASSESSMENT FAILED",
            detail=_last_error,
        )
    finally:
        _run_lock.release()


@app.get("/healthz")
def healthz():
    return jsonify({
        "status": "ok",
        "service": "sentinel-pentest",
        "storage": {
            "data_dir": os.getenv("SENTINEL_DATA_DIR", "local"),
            "evidence_dir": config.EVIDENCE_DIR,
            "report_dir": config.REPORT_DIR,
        },
    })


@app.get("/")
def index():
    auth = _require_auth()
    if auth:
        return auth

    # Browser navigation cannot preserve a custom X-Sentinel-Token header.
    # When the console is opened with ?token=..., establish a short-lived
    # HttpOnly same-origin cookie so report/evidence links and polling continue
    # to authenticate without exposing the token in every asset URL.
    response = app.make_response(_HTML)
    if ACCESS_TOKEN and request.args.get("token") == ACCESS_TOKEN:
        response.set_cookie(
            "sentinel_access_token",
            ACCESS_TOKEN,
            httponly=True,
            secure=request.is_secure,
            samesite="Lax",
            max_age=3600,
        )
    return response


def _coverage_payload(report: dict | None) -> dict:
    """Build independently reviewable coverage sections from the canonical report."""
    report = report or {}
    metadata = report.get("metadata") or {}
    framework = report.get("framework_coverage") or build_coverage_registry(metadata.get("phase_status") or {})
    owasp_2025 = report.get("owasp_top10_2025_coverage") or [
        {"code": code, "name": name, "status": "not_run", "phases": [],
         "limitation": "No assessment report is available yet; this category has not been assessed."}
        for code, name in [
            ("A01:2025", "Broken Access Control"),
            ("A02:2025", "Security Misconfiguration"),
            ("A03:2025", "Software Supply Chain Failures"),
            ("A04:2025", "Cryptographic Failures"),
            ("A05:2025", "Injection"),
            ("A06:2025", "Insecure Design"),
            ("A07:2025", "Authentication Failures"),
            ("A08:2025", "Software or Data Integrity Failures"),
            ("A09:2025", "Security Logging & Alerting Failures"),
            ("A10:2025", "Mishandling of Exceptional Conditions"),
        ]
    ]
    owasp_2021 = report.get("owasp_coverage") or [
        {"code": code, "name": name, "status": "not_run", "phases": [],
         "limitation": "No assessment report is available yet; this category has not been assessed."}
        for code, name in [
            ("A01:2021", "Broken Access Control"),
            ("A02:2021", "Cryptographic Failures"),
            ("A03:2021", "Injection"),
            ("A04:2021", "Insecure Design"),
            ("A05:2021", "Security Misconfiguration"),
            ("A06:2021", "Vulnerable and Outdated Components"),
            ("A07:2021", "Identification and Authentication Failures"),
            ("A08:2021", "Software and Data Integrity Failures"),
            ("A09:2021", "Security Logging and Monitoring Failures"),
            ("A10:2021", "Server-Side Request Forgery"),
        ]
    ]

    wstg = [row for row in framework if "OWASP WSTG" in str(row.get("standard", ""))]
    api = [row for row in framework if str(row.get("id", "")).startswith("API-")]
    wcag = [row for row in framework if str(row.get("id", "")).startswith("WCAG-")]
    supplemental = [
        row for row in framework
        if str(row.get("standard", "")).lower() == "sentinel"
        and not str(row.get("id", "")).startswith(("API-", "WCAG-"))
    ]
    sections = [
        {"id": "wstg", "title": "OWASP Web Security Testing Guide (WSTG)", "standard": "OWASP WSTG v4.2", "items": wstg},
        {"id": "owasp-2025", "title": "OWASP Top 10:2025", "standard": "OWASP Top 10:2025", "items": owasp_2025},
        {"id": "owasp-2021", "title": "OWASP Top 10:2021 (legacy comparison)", "standard": "OWASP Top 10:2021", "items": owasp_2021},
        {"id": "api-top10", "title": "OWASP API Security Top 10:2023", "standard": "OWASP API Security Top 10:2023", "items": api},
        {"id": "wcag", "title": "Accessibility", "standard": "W3C WCAG 2.2 AA automated heuristics", "items": wcag},
        {"id": "supplemental", "title": "Sentinel Supplemental Coverage", "standard": "Sentinel", "items": supplemental},
    ]
    counts = {"engines_completed": 0, "partial": 0, "partial_or_failed": 0, "not_run": 0, "manual_review": 0}
    total = 0
    for section in sections:
        for item in section["items"]:
            total += 1
            status = str(item.get("status", "not_run")).lower()
            if status in {"complete", "completed", "engines_completed"}:
                counts["engines_completed"] += 1
            elif status in {"partial_or_failed", "failed", "timed_out", "blocked"}:
                counts["partial_or_failed"] += 1
            elif status in {"partial", "in_progress"}:
                counts["partial"] += 1
            elif status == "manual_review":
                counts["manual_review"] += 1
            else:
                counts["not_run"] += 1
    return {
        "ready": bool(report),
        "target": report.get("target"),
        "generated_at": report.get("generated_at"),
        "overall_status": metadata.get("status") or report.get("assessment_status") or "not available",
        "phase_status": metadata.get("phase_status") or {},
        "sections": sections,
        "summary": {"total_areas": total, **counts},
    }


@app.get("/api/coverage")
def coverage():
    auth = _require_auth()
    if auth:
        return auth
    report_path = Path(config.REPORT_DIR) / "findings.json"
    report = None
    if report_path.is_file():
        try:
            with report_path.open("r", encoding="utf-8") as handle:
                report = json.load(handle)
        except (OSError, json.JSONDecodeError):
            report = None
    return jsonify(_coverage_payload(report))


@app.get("/api/status")
def status():
    auth = _require_auth()
    if auth:
        return auth
    payload = _state.snapshot()
    payload["running"] = _run_lock.locked()
    payload["last_result"] = _last_result
    payload["last_error"] = _last_error
    active_profile = str(payload.get("profile") or "pentest")
    core_mode = active_profile == "core"
    bundle_path = Path(config.REPORT_DIR) / ("sentinel_core_bundle.zip" if core_mode else "sentinel_full_report_bundle.zip")
    report_path = Path(config.REPORT_DIR) / ("core_report.html" if core_mode else "report.html")
    # Render may restart the web worker after a scan. The in-memory dashboard
    # state then resets to INITIALIZING even though report artifacts remain on
    # the persistent disk. Publish artifact readiness independently of the
    # transient worker status so users can still download the completed report.
    bundle_ready = bundle_path.is_file() and bundle_path.stat().st_size > 0
    report_ready = report_path.is_file() and report_path.stat().st_size > 0
    bundle_mtime = bundle_path.stat().st_mtime if bundle_ready else None
    bundle_for_current_run = bool(
        bundle_ready and _run_started_at is not None and bundle_mtime is not None
        and bundle_mtime >= _run_started_at
    )
    payload["reports"] = {
        "profile": active_profile,
        "html": "/reports/core_report.html" if core_mode else "/reports/report.html",
        "portable_html": "" if core_mode else "/reports/report_portable.html",
        "pdf": "" if core_mode else "/reports/report.pdf",
        "xlsx": "" if core_mode else "/reports/penetration_report.xlsx",
        "findings_json": "/reports/core_report.json" if core_mode else "/reports/findings.json",
        "manifest": "" if core_mode else "/reports/evidence_manifest.json",
        "sarif": "" if core_mode else "/reports/sentinel.sarif",
        "bundle": "/reports/sentinel_core_bundle.zip" if core_mode else "/reports/sentinel_full_report_bundle.zip",
        "bundle_filename": "sentinel_core_bundle.zip" if core_mode else "sentinel_full_report_bundle.zip",
        "bundle_ready": bundle_ready,
        "bundle_for_current_run": bundle_for_current_run,
        "report_ready": report_ready,
        "bundle_size_bytes": bundle_path.stat().st_size if bundle_ready else 0,
        "bundle_modified_at": bundle_mtime,
        "run_started_at": _run_started_at,
    }
    if core_mode:
        core_state = str(payload.get("status") or "pending").lower()
        payload["coverage"] = {
            "ui_responsive": "not run",
            "functional": "not run",
            "security": core_state if core_state in {"complete", "partial", "failed"} else ("running" if payload["running"] else "pending"),
            "penetration": "core subset",
            "information_disclosure": "included",
            "evidence": "captured" if bundle_ready else ("running" if payload["running"] else "pending"),
        }
    return jsonify(payload)


@app.post("/api/run")
def run():
    global _run_thread, _state, _last_result, _run_started_at
    auth = _require_auth()
    if auth:
        return auth

    if not _run_lock.acquire(blocking=False):
        return jsonify({"error": "assessment_already_running"}), 409

    body = request.get_json(silent=True) or {}
    target = str(body.get("target") or DEFAULT_TARGET).strip().rstrip("/")
    authorized = bool(body.get("authorized", False))
    profile = str(body.get("profile") or "pentest").strip().lower()
    if profile not in {"pentest", "core"}:
        _run_lock.release()
        return jsonify({
            "error": "invalid_profile",
            "message": "Profile must be 'pentest' or 'core'.",
        }), 400

    if not target.startswith(("http://", "https://")):
        _run_lock.release()
        return jsonify({
            "error": "invalid_target",
            "message": "Target must be a complete http:// or https:// URL.",
        }), 400

    if not authorized:
        _run_lock.release()
        return jsonify({
            "error": "authorization_confirmation_required",
            "message": "Confirm that you own the target or have explicit permission to assess it.",
        }), 400

    _state = DashboardState(target=target, profile=profile)
    _state.update(
        status="RUNNING",
        stage="QUEUED",
        detail="Assessment worker starting...",
        progress=0,
    )
    _last_result = None
    _run_started_at = time.time()

    _run_thread = threading.Thread(target=_worker, args=(target, profile), daemon=True)
    _run_thread.start()
    return jsonify({"accepted": True, "target": target, "profile": profile}), 202


def _artifact(directory: str, filename: str):
    auth = _require_auth()
    if auth:
        return auth
    base = Path(directory).resolve()
    requested = Path(filename)
    if requested.is_absolute() or ".." in requested.parts:
        return jsonify({"error": "invalid_path"}), 400
    full = (base / requested).resolve()
    if base != full and base not in full.parents:
        return jsonify({"error": "invalid_path"}), 400
    if not full.is_file():
        return jsonify({"error": "not_found"}), 404

    response = send_from_directory(str(base), str(full.relative_to(base)))
    # Reports are regenerated during an assessment; never let a stale cached
    # HTML/JSON/image response hide the newest findings or evidence links.
    if base in {Path(config.REPORT_DIR).resolve(), Path(config.EVIDENCE_DIR).resolve()}:
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        response.headers["Pragma"] = "no-cache"
        # Keep artifact MIME types explicit on Render/CDN paths so PNG/JPEG
        # evidence is rendered as an image instead of being treated as an
        # attachment or generic binary response.
        suffix = full.suffix.lower()
        if suffix == ".png":
            response.headers["Content-Type"] = "image/png"
        elif suffix in {".jpg", ".jpeg"}:
            response.headers["Content-Type"] = "image/jpeg"
        elif suffix == ".webp":
            response.headers["Content-Type"] = "image/webp"
        elif suffix in {".json", ".sarif"}:
            response.headers["Content-Type"] = "application/sarif+json; charset=utf-8" if suffix == ".sarif" else "application/json; charset=utf-8"
        elif suffix == ".html":
            response.headers["Content-Type"] = "text/html; charset=utf-8"
        elif suffix == ".zip":
            response.headers["Content-Type"] = "application/zip"
            response.headers["Content-Disposition"] = f'attachment; filename="{full.name}"'
    return response


@app.get("/reports/<path:filename>")
def reports(filename):
    return _artifact(config.REPORT_DIR, filename)


@app.get("/evidence/<path:filename>")
def evidence(filename):
    return _artifact(config.EVIDENCE_DIR, filename)


_HTML = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Sentinel // Hosted Pentest Console</title>
<style>
:root{--bg:#03060b;--panel:#0a111b;--line:#193149;--text:#e7f1fb;--muted:#7891a9;--green:#38e8a0;--blue:#4ea1ff;--red:#ff3864;--yellow:#ffc857}
*{box-sizing:border-box}body{margin:0;background:radial-gradient(circle at 50% 0,#123047 0,#04070d 45%,#020307 100%);color:var(--text);font:14px/1.5 Inter,Segoe UI,Arial,sans-serif;min-height:100vh}.wrap{max-width:1250px;margin:auto;padding:22px}.top{display:flex;justify-content:space-between;gap:16px;align-items:center;margin-bottom:16px}.brand{font-weight:900;letter-spacing:.12em}.badge{border:1px solid var(--line);border-radius:999px;padding:7px 12px;color:var(--green);background:#06150f}.grid{display:grid;grid-template-columns:1.1fr .9fr;gap:14px}.panel{background:#07101bf2;border:1px solid var(--line);border-radius:16px;box-shadow:0 18px 70px #0008;overflow:hidden}.pad{padding:18px}h2,h3{margin-top:0}.muted{color:var(--muted)}label{display:block;color:var(--muted);font-size:12px;margin:12px 0 6px;text-transform:uppercase;letter-spacing:.08em}input,select{width:100%;padding:12px;border:1px solid var(--line);border-radius:10px;background:#03070d;color:var(--text)}button{margin-top:14px;width:100%;padding:12px;border:0;border-radius:10px;background:linear-gradient(90deg,var(--blue),var(--green));color:#02100b;font-weight:900;cursor:pointer}.hero{min-height:390px;position:relative;display:flex;align-items:center;justify-content:center;text-align:center}.ring{width:210px;height:210px;border:1px solid #38e8a066;border-radius:50%;box-shadow:0 0 70px #38e8a01a,inset 0 0 50px #38e8a01a;animation:pulse 2.2s ease-in-out infinite}.core{position:absolute;width:72px;height:72px;border-radius:50%;border:1px solid var(--green);box-shadow:0 0 45px #38e8a055;background:#38e8a014}.center{position:absolute;padding:0 30px}.stage{font-size:20px;font-weight:900;letter-spacing:.08em;margin-top:18px}.detail{color:var(--muted);margin-top:6px}@keyframes pulse{50%{transform:scale(1.08);opacity:.72}}.bar{height:9px;background:#101b29;border-radius:99px;overflow:hidden;margin:10px 0}.fill{height:100%;width:0;background:linear-gradient(90deg,var(--blue),var(--green));transition:width .35s}.metrics{display:grid;grid-template-columns:repeat(4,1fr);gap:8px}.metric{border:1px solid var(--line);border-radius:10px;padding:10px;background:#08121e}.metric b{display:block;font-size:21px}.metric span{color:var(--muted);font-size:10px;text-transform:uppercase}.evidence{margin-top:14px}.evidencebox{display:grid;grid-template-columns:repeat(3,1fr);gap:10px;padding:14px;max-height:560px;overflow:auto}.e-card{border:1px solid var(--line);border-radius:12px;background:#03070d;overflow:hidden}.e-card img{width:100%;height:145px;object-fit:contain;background:#02050a;display:block}.e-body{padding:9px}.e-id{font-weight:900;color:var(--green);font-size:11px}.e-url{font-size:10px;color:var(--muted);word-break:break-all;margin-top:4px}.e-body a{display:inline-block;margin-top:7px;color:var(--blue);text-decoration:none;font-size:11px}.coverage{display:grid;grid-template-columns:repeat(6,1fr);gap:8px;margin-top:14px}.cov{border:1px solid var(--line);border-radius:10px;padding:10px;background:#08121e}.cov b{display:block;font-size:11px}.cov span{display:block;color:var(--muted);font-size:9px;text-transform:uppercase;margin-top:4px}.links{display:grid;gap:8px;margin-top:14px}.links a{color:var(--green);text-decoration:none;border:1px solid var(--line);padding:9px;border-radius:9px}.logs{margin-top:14px;height:220px;overflow:auto;background:#02050a;border-top:1px solid var(--line);padding:12px;font:12px/1.6 Consolas,monospace}.ok{color:var(--green)}.err{color:var(--red)}.warn{color:var(--yellow)}@media(max-width:1050px){.coverage{grid-template-columns:repeat(3,1fr)}.evidencebox{grid-template-columns:repeat(2,1fr)}}@media(max-width:900px){.grid{grid-template-columns:1fr}.metrics{grid-template-columns:repeat(2,1fr)}.coverage{grid-template-columns:repeat(2,1fr)}.evidencebox{grid-template-columns:1fr}.wrap{padding:12px}}

/* Sentinel Professional Console v2 */
:root{color-scheme:dark;--bg:#0b1120;--panel:#111a2b;--line:#27364d;--text:#edf3fc;--muted:#91a2ba;--green:#55e6ad;--blue:#76a9ff;--red:#ff7188;--yellow:#f6c96b}
body{background:#0b1120;color:var(--text);font-family:Inter,ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif;letter-spacing:0}
.wrap{max-width:1480px;padding:28px 30px}
.top{padding:8px 0 22px;border-bottom:1px solid #263349;margin-bottom:24px}
.brand{font-size:16px;letter-spacing:.04em;display:flex;align-items:center;gap:12px}
.brand:before{content:"S";display:grid;place-items:center;width:38px;height:38px;border-radius:11px;background:#173c3b;color:#65f0bd;border:1px solid #28665b;font-size:19px}
.badge{background:#102d27;border-color:#285c50;color:#6cebb7;font-size:12px;font-weight:700}
.grid{grid-template-columns:minmax(0,1.45fr) minmax(330px,.75fr);gap:18px}
.panel{background:#111a2b;border:1px solid #27364d;border-radius:14px;box-shadow:0 10px 28px #02061735}
.pad{padding:22px}
h2{font-size:18px;letter-spacing:-.02em}h3{font-size:12px;color:#a7b7ce;letter-spacing:.09em}
.muted,.detail{color:#91a2ba}
input{background:#0b1220;border:1px solid #34435a;border-radius:9px;padding:13px 14px;outline:none}
input:focus{border-color:#76a9ff;box-shadow:0 0 0 3px #76a9ff22}
button{background:#4bd5a2;color:#06261d;border-radius:9px;font-size:13px;letter-spacing:.01em;box-shadow:none;transition:filter .15s,transform .15s}
button:hover{filter:brightness(1.08);transform:translateY(-1px)}
.hero{min-height:370px;background:radial-gradient(ellipse at 50% 38%,#183747 0,#111a2b 60%)}
.ring{border-color:#55e6ad65;box-shadow:0 0 55px #55e6ad15,inset 0 0 40px #55e6ad0c}
.core{border-color:#55e6ad;background:#55e6ad12}
.bar{background:#273449;height:8px}
.fill{background:linear-gradient(90deg,#76a9ff,#55e6ad);border-radius:99px}
.metric{background:#0d1626;border:1px solid #27364d;border-radius:11px;padding:14px}
.metric b{font-size:24px;font-weight:650;letter-spacing:-.04em}
.metric span{font-size:10px;letter-spacing:.1em;color:#91a2ba}
.coverage-card{background:#0d1626;border-color:#27364d;border-radius:10px;padding:13px}
.evidencebox{padding:16px;gap:14px}
.e-card{background:#0b1220;border-color:#2a3b53;border-radius:10px}
.e-card img{height:170px}
.e-id{color:#69e8b5}
.logs{margin-top:18px}
.logbox{background:#080e19;border-top-color:#27364d;height:230px}
table{font-size:12px}th,td{padding:11px 10px;border-bottom-color:#25344a}th{font-weight:650}
hr{border-top-color:#27364d!important}
@media(max-width:900px){.wrap{padding:14px}.grid{grid-template-columns:1fr}.hero{min-height:330px}.top{align-items:flex-start}.brand{font-size:13px}.panel{border-radius:12px}}


.coverage-report .coverage-heading{display:flex;justify-content:space-between;align-items:flex-start;gap:16px}
.coverage-summary{display:grid;grid-template-columns:repeat(6,minmax(0,1fr));gap:8px;margin:18px 0}
.coverage-stat{background:#0d1626;border:1px solid #27364d;border-radius:10px;padding:12px}
.coverage-stat b{display:block;font-size:20px}.coverage-stat span{display:block;color:var(--muted);font-size:10px;margin-top:3px}
.coverage-filters{display:grid;grid-template-columns:1fr 1fr 1.4fr;gap:12px;align-items:end;margin:12px 0 18px}
.coverage-filters label{margin-top:0}.coverage-filters select,.coverage-filters input{width:100%;min-width:0}
.coverage-section{border:1px solid #27364d;border-radius:11px;margin:10px 0;overflow:hidden;background:#0d1626}
.coverage-section-head{display:flex;justify-content:space-between;gap:12px;align-items:center;padding:12px 14px;background:#111d30}
.coverage-section-head h3{margin:0;color:var(--text);font-size:13px;letter-spacing:0}
.coverage-section-head span{font-size:11px;color:var(--muted)}
.coverage-item{border-top:1px solid #25344a;padding:0 14px}
.coverage-item summary{cursor:pointer;list-style:none;display:grid;grid-template-columns:minmax(70px,110px) minmax(0,1fr) auto;gap:10px;align-items:center;padding:12px 0}
.coverage-item summary::-webkit-details-marker{display:none}
.coverage-code{font:11px Consolas,monospace;color:#76a9ff;overflow-wrap:anywhere}
.coverage-name{font-weight:650;font-size:12px}.coverage-status{font-size:10px;border:1px solid #34435a;border-radius:99px;padding:4px 7px;white-space:nowrap;color:var(--muted)}
.coverage-status.completed{color:#69e8b5;border-color:#28665b}.coverage-status.partial{color:#f6c96b;border-color:#75602f}.coverage-status.failed{color:#ff7188;border-color:#793347}.coverage-status.manual{color:#c4b5fd;border-color:#55457b}
.coverage-detail{padding:0 0 14px 0;font-size:12px;color:#b6c5d8}.coverage-detail p{margin:7px 0}.coverage-detail ul{margin:6px 0;padding-left:20px}.phase-pill{display:inline-block;border:1px solid #34435a;border-radius:6px;padding:4px 7px;margin:3px 4px 3px 0;font:10px Consolas,monospace;overflow-wrap:anywhere}
.coverage-empty{padding:16px;border:1px dashed #34435a;border-radius:10px;color:var(--muted)}
@media(max-width:900px){.coverage-summary{grid-template-columns:repeat(2,minmax(0,1fr))}.coverage-filters{grid-template-columns:1fr}.coverage-report .coverage-heading{flex-direction:column}.coverage-item summary{grid-template-columns:1fr auto}.coverage-code{grid-column:1/-1}.coverage-name{min-width:0}.coverage-status{grid-column:2;grid-row:2}}
</style></head>
<body><main class="wrap">
<header class="top"><div class="brand">SENTINEL // HOSTED PENTEST CONSOLE</div><div id="status" class="badge">IDLE</div></header>
<div class="grid">
<section class="panel hero"><div class="ring"></div><div class="core"></div><div class="center"><div class="stage" id="stage">READY</div><div class="detail" id="detail">Start an authorized assessment.</div></div></section>
<aside class="panel pad"><h3>Start Assessment</h3>
<div class="muted">Step 1 — enter the web URL. Nothing is scanned until you submit it.</div>
<label>Web URL</label><input id="target" value="__DEFAULT_TARGET__" placeholder="https://example.com" autocomplete="url" inputmode="url">
<label for="profile">Assessment profile</label><select id="profile"><option value="pentest">Full Pentest — browser, security and evidence pipeline</option><option value="core">Core Security — bounded read-only checks and evidence bundle</option></select>
<label style="display:flex;gap:9px;align-items:flex-start;text-transform:none;letter-spacing:0;font-size:12px;color:var(--text);margin-top:14px"><input id="authorized" type="checkbox" style="width:auto;margin-top:2px"> <span>I confirm I own this website or have explicit permission to perform security testing against it.</span></label>
<button id="startBtn" type="button">START PENTEST</button>
<div class="metrics" style="margin-top:14px"><div class="metric"><b id="pages">0</b><span>pages</span></div><div class="metric"><b id="checks">0</b><span>checks</span></div><div class="metric"><b id="findings">0</b><span>findings</span></div><div class="metric"><b id="errors">0</b><span>errors</span></div></div>
<div style="margin-top:18px"><div id="pct">0%</div><div class="bar"><div id="fill" class="fill"></div></div></div>
<div class="links"><a id="reportLink" href="/reports/report.html" target="_blank">Open live HTML report</a><div id="completionDownloads" style="display:none;border:1px solid var(--green);border-radius:10px;padding:12px;background:#06150f"><strong style="color:var(--green)">ASSESSMENT COMPLETE — REPORTS READY</strong><p class="muted" style="margin:6px 0 10px">The final report bundle includes the reports, findings, manifest and captured evidence files.</p><a id="downloadBundle" href="/reports/sentinel_full_report_bundle.zip" download="sentinel_full_report_bundle.zip" style="display:block;text-align:center;background:var(--green);color:#03110b;font-weight:900">⬇ DOWNLOAD COMPLETE REPORT + EVIDENCE (ZIP)</a></div><a id="portableLink" href="/reports/report_portable.html" target="_blank">Portable report</a><a id="findingsJsonLink" href="/reports/findings.json" target="_blank">Findings JSON</a><a id="manifestLink" href="/reports/evidence_manifest.json" target="_blank">Evidence manifest</a><a id="sarifLink" href="/reports/sentinel.sarif" target="_blank">SARIF for CI tools</a><a id="pdfLink" href="/reports/report.pdf" target="_blank">PDF report</a><a id="xlsxLink" href="/reports/penetration_report.xlsx" target="_blank">XLSX report</a></div><div id="reportNotice" class="muted" style="margin-top:10px">The download button appears only after the assessment reaches its final status. Reports are not downloaded during a running assessment.</div>
</aside></div>
<section class="panel evidence"><div class="pad"><h3 style="margin:0">Live Evidence Stream</h3><div class="muted">Focused security evidence appears here during the browser evidence phase.</div></div><div id="evidence" class="evidencebox"><div class="muted pad">Waiting for captured evidence...</div></div></section>
<section class="panel coverage-report" id="coverageReport" style="margin-top:14px">
<div class="pad">
  <div class="coverage-heading"><div><h2 style="margin:0 0 5px">Section-by-Section Coverage</h2><div class="muted">Each category shows mapped phases, execution status, limitations, and manual-review requirements. Completed engines are not a security certification.</div></div><button id="refreshCoverage" type="button" style="width:auto;min-width:130px;margin:0">REFRESH COVERAGE</button></div>
  <div id="coverageSummary" class="coverage-summary"><div class="muted">Loading coverage registry…</div></div>
  <div class="coverage-filters">
    <div><label for="coverageSectionFilter">Coverage standard / section</label><select id="coverageSectionFilter"><option value="all">All coverage sections</option></select></div>
    <div><label for="coverageStatusFilter">Execution status</label><select id="coverageStatusFilter"><option value="all">All statuses</option><option value="engines_completed">Engine completed</option><option value="partial">Partial / in progress</option><option value="partial_or_failed">Failed / timed out / blocked</option><option value="not_run">Not run</option><option value="manual_review">Manual review</option></select></div>
    <div><label for="coverageSearch">Search category or phase</label><input id="coverageSearch" type="search" placeholder="Search e.g. injection, authorization, WCAG…"></div>
  </div>
  <div id="coverageSections" class="coverage-sections"><div class="muted">Coverage details will appear here.</div></div>
  <div id="coverageFooter" class="muted" style="font-size:11px;margin-top:12px">Coverage is based on the latest report ledger. Missing prerequisites remain incomplete or manual-review only.</div>
</div>
</section>
<section class="coverage">
<div class="cov"><b>UI / Responsive</b><span id="cov-ui">PENDING</span></div><div class="cov"><b>Functional</b><span id="cov-functional">PENDING</span></div><div class="cov"><b>Security</b><span id="cov-security">PENDING</span></div><div class="cov"><b>Penetration</b><span id="cov-penetration">PENDING</span></div><div class="cov"><b>Info Leak</b><span id="cov-info">PENDING</span></div><div class="cov"><b>Evidence</b><span id="cov-evidence">PENDING</span></div>
</section>
<section class="panel" style="margin-top:14px"><div class="pad"><h3>Live execution log</h3></div><div id="logs" class="logs"></div></section>
</main>
<script>
const el = (id) => document.getElementById(id);
let pollTimer = null;
let autoDownloadPending = false;
let autoDownloadStarted = false;

function showState(status, stage, detail) {
  el("status").textContent = status || "IDLE";
  el("stage").textContent = stage || "READY";
  el("detail").textContent = detail || "";
}

function setButton(running, label) {
  const btn = el("startBtn");
  btn.disabled = !!running;
  btn.textContent = label || (running ? "RUNNING..." : "START PENTEST");
}

async function startRun() {
  const btn = el("startBtn");
  const targetInput = el("target");
  const authInput = el("authorized");

  const target = (targetInput.value || "").trim().replace(/\/$/, "");
  const authorized = !!authInput.checked;

  if (!target) {
    showState("READY", "TARGET REQUIRED", "Enter https://amwebtech.com before starting.");
    targetInput.focus();
    return;
  }

  const lower = target.toLowerCase();
  if (!(lower.startsWith("http://") || lower.startsWith("https://"))) {
    showState("READY", "INVALID TARGET", "Target must start with http:// or https://.");
    targetInput.focus();
    return;
  }

  if (!authorized) {
    showState("READY", "AUTHORIZATION REQUIRED", "Confirm that you own the target or have explicit permission to test it.");
    return;
  }

  setButton(true, "STARTING...");
  showState("STARTING", "CONNECTING", "Submitting the assessment request...");

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 25000);
    let response;
    try {
      response = await fetch("/api/run?ts=" + Date.now(), {
        method: "POST",
        cache: "no-store",
        credentials: "same-origin",
        headers: {
          "Content-Type": "application/json",
          "Accept": "application/json",
          "Cache-Control": "no-cache"
        },
        body: JSON.stringify({ target: target, authorized: true, profile: el("profile").value }),
        signal: controller.signal
      });
    } finally {
      clearTimeout(timeout);
    }

    const bodyText = await response.text();
    let data = {};
    try {
      data = bodyText ? JSON.parse(bodyText) : {};
    } catch (_) {
      data = { message: bodyText || "Server returned an invalid response." };
    }

    if (!response.ok) {
      throw new Error(data.message || data.error || ("Server returned HTTP " + response.status));
    }

    autoDownloadPending = true;
    autoDownloadStarted = false;
    const selectedProfile = el("profile").value;
    showState("RUNNING", "QUEUED", selectedProfile === "core"
      ? "Core security assessment accepted. The HTML/JSON report and evidence ZIP will be ready when checks finish."
      : "Full pentest accepted. The complete report ZIP will download automatically when it is ready.");
    setButton(true, "PENTEST RUNNING");
  } catch (error) {
    const message = error && error.name === "AbortError"
      ? "The server did not respond within 25 seconds. Check Render health/logs before retrying."
      : (error && error.message === "Failed to fetch"
        ? "Render disconnected before returning a response. The service may be restarting or overloaded; status polling will retry automatically."
        : (error && error.message ? error.message : "Unable to start the assessment."));

    showState("ERROR", "START FAILED", message);
    setButton(false, "START PENTEST");
  }
}

function renderStatus(s) {
  const running = !!s.running;
  el("status").textContent = running ? "RUNNING" : (s.status || "IDLE");
  el("stage").textContent = s.stage || "READY";
  el("detail").textContent = s.detail || "";
  el("pages").textContent = s.pages_tested || 0;
  el("checks").textContent = s.checks || 0;
  el("findings").textContent = s.findings || 0;
  el("errors").textContent = s.errors || 0;

  const progress = Number(s.progress || 0);
  el("pct").textContent = progress + "%";
  el("fill").style.width = progress + "%";

  const reportLink = el("reportLink");
  const reportNotice = el("reportNotice");
  if (reportLink) {
    reportLink.href = (s.reports && s.reports.html ? s.reports.html : "/reports/report.html") + "?ts=" + Date.now();
  }
  const completionDownloads = el("completionDownloads");
  const downloadBundle = el("downloadBundle");
  const reports = s.reports || {};
  const coreMode = reports.profile === "core";
  const findingsJsonLink = el("findingsJsonLink");
  if (findingsJsonLink) findingsJsonLink.href = (reports.findings_json || "/reports/findings.json") + "?ts=" + Date.now();
  const completionTitle = document.querySelector("#completionDownloads strong");
  const completionText = document.querySelector("#completionDownloads p");
  if (coreMode && completionTitle) completionTitle.textContent = "CORE ASSESSMENT FINISHED — REPORTS READY";
  if (coreMode && completionText) completionText.textContent = "The core bundle includes HTML/JSON results and captured request evidence.";
  const linkIds = ["reportLink", "downloadBundle", "findingsJsonLink", "portableLink", "manifestLink", "sarifLink", "pdfLink", "xlsxLink"];
  linkIds.forEach(function(id) {
    const node = el(id);
    if (node) node.style.display = coreMode ? (["reportLink", "downloadBundle", "findingsJsonLink"].includes(id) ? "block" : "none") : "";
  });
  const finalStatus = ["COMPLETE", "PARTIAL", "FAILED"].indexOf(String(s.status || "").toUpperCase()) >= 0;
  // Show the action only when a run has ended OR a complete bundle already
  // exists on persistent storage after a worker restart. Never show it during
  // an active scan. This avoids the stuck INITIALIZING screen hiding a report
  // that was already generated successfully.
  const bundleReady = reports.bundle_ready === true;
  const currentBundleReady = reports.bundle_for_current_run === true;
  const downloadReady = !running && (finalStatus || bundleReady);
  if (completionDownloads) {
    completionDownloads.style.display = downloadReady ? "block" : "none";
  }
  if (downloadBundle) {
    downloadBundle.href = (reports.bundle || "/reports/sentinel_full_report_bundle.zip") + "?download=1&ts=" + Date.now();
    downloadBundle.setAttribute("download", reports.bundle_filename || "sentinel_full_report_bundle.zip");
    downloadBundle.textContent = coreMode
      ? (currentBundleReady && s.status === "COMPLETE"
        ? "⬇ DOWNLOAD CORE REPORT + EVIDENCE (ZIP)"
        : (currentBundleReady ? "⬇ DOWNLOAD PARTIAL CORE REPORT (ZIP)" : "CORE REPORT BUNDLE NOT READY"))
      : (currentBundleReady && s.status === "COMPLETE"
        ? "⬇ DOWNLOAD COMPLETE REPORT + ALL EVIDENCE (ZIP)"
        : (currentBundleReady
          ? "⬇ DOWNLOAD PARTIAL REPORT + AVAILABLE EVIDENCE (ZIP)"
          : (bundleReady ? "⬇ DOWNLOAD PREVIOUS REPORT + EVIDENCE (ZIP)" : "REPORT BUNDLE NOT READY")));
    downloadBundle.setAttribute("aria-disabled", currentBundleReady ? "false" : "true");
  }
  // Automatically start a single ZIP download for the current assessment after
  // the server confirms that the bundle was generated after this run began.
  // This avoids silently downloading an old bundle after a failed export.
  if (!running && autoDownloadPending && !autoDownloadStarted && currentBundleReady && downloadBundle) {
    autoDownloadStarted = true;
    autoDownloadPending = false;
    reportNotice && (reportNotice.textContent = "Assessment finished. Downloading the complete report bundle with all packaged evidence now.");
    downloadBundle.click();
  } else if (!running && autoDownloadPending && finalStatus && !currentBundleReady) {
    autoDownloadPending = false;
    reportNotice && (reportNotice.textContent = "Assessment ended, but a fresh complete ZIP was not generated. Check the execution log and use the report links for available partial artifacts.");
  }
  if (reportNotice) {
    if (running) reportNotice.textContent = "Assessment is running. No final download is triggered; the report bundle button appears only when execution ends.";
    else if (s.status === "FAILED") reportNotice.textContent = coreMode ? "Core assessment failed. Review the error and any available partial artifacts." : "Assessment stopped with an error. A partial report bundle is available below; review failed phases before relying on its coverage.";
    else if (s.status === "PARTIAL") reportNotice.textContent = coreMode ? "Core assessment finished with incomplete phases. Failed or skipped checks are not counted as passes." : "Assessment finished with incomplete phases. Download the partial bundle below; timed-out or failed checks are not considered passed.";
    else if (s.status === "COMPLETE" && currentBundleReady) reportNotice.textContent = coreMode ? "Core assessment complete. The HTML/JSON report and request-evidence ZIP are ready." : "Assessment complete. The complete report + evidence ZIP is ready and will download automatically after a newly launched run.";
    else if (reports.bundle_ready === true) reportNotice.textContent = "A previous report bundle is available below. It is not treated as the output of the current run unless its timestamp confirms that it was freshly generated.";
    else reportNotice.textContent = "Start an authorized assessment. The final report download will appear after it ends.";
  }
  if (running) {
    setButton(true, "PENTEST RUNNING");
  } else {
    setButton(false, "START PENTEST");
  }

  const cov = s.coverage || {};
  [["ui","ui_responsive"],["functional","functional"],["security","security"],["penetration","penetration"],["info","information_disclosure"],["evidence","evidence"]].forEach(function(pair){
    const node = el("cov-"+pair[0]); if(node) node.textContent = String(cov[pair[1]] || "pending").toUpperCase();
  });
  const evidence = Array.isArray(s.live_evidence) ? s.live_evidence.slice().reverse() : [];
  const evidenceBox = el("evidence");
  if (evidenceBox) {
    evidenceBox.innerHTML = evidence.length ? evidence.map(function(item){
      const src = String(item.artifact_url || "");
      return '<article class="e-card"><img loading="lazy" src="'+src+'" alt="Focused evidence '+String(item.finding_id||"")+'"><div class="e-body"><div class="e-id">'+String(item.finding_id||"EVIDENCE")+'</div><div class="e-url">'+String(item.url||"")+'</div><div class="muted" style="font-size:10px;margin-top:5px">'+String(item.capture_mode||"artifact")+'</div><a href="'+src+'" target="_blank" rel="noopener">Open evidence</a></div></article>';
    }).join("") : '<div class="muted pad">No evidence captured yet. Security findings are evidenced as the browser phase runs.</div>';
  }

  const logs = Array.isArray(s.logs) ? s.logs.slice(-160) : [];
  el("logs").innerHTML = logs.map(function(item) {
    const level = String(item.level || "");
    const time = String(item.time || "");
    const message = String(item.message || "").replace(/[&<>]/g, function(ch) {
      return {"&":"&amp;","<":"&lt;",">":"&gt;"}[ch];
    });
    return '<div class="' + level + '">[' + time + '] ' + message + '</div>';
  }).join("");

  el("logs").scrollTop = el("logs").scrollHeight;
}

let coveragePayload = null;
let coverageLoading = false;
let coverageLastLoaded = 0;

function coverageEscape(value) {
  return String(value == null ? "" : value).replace(/[&<>"']/g, function(ch) {
    return {"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[ch];
  });
}
function coverageStatusLabel(status) {
  const labels = {engines_completed:"ENGINE COMPLETED",completed:"ENGINE COMPLETED",partial:"PARTIAL",in_progress:"IN PROGRESS",partial_or_failed:"FAILED / INCOMPLETE",failed:"FAILED",timed_out:"TIMED OUT",blocked:"BLOCKED",not_run:"NOT RUN",manual_review:"MANUAL REVIEW"};
  return labels[String(status || "not_run").toLowerCase()] || String(status || "NOT RUN").replace(/_/g, " ").toUpperCase();
}
function coverageStatusClass(status) {
  status = String(status || "not_run").toLowerCase();
  if (["engines_completed","completed"].includes(status)) return "completed";
  if (["partial","in_progress"].includes(status)) return "partial";
  if (["partial_or_failed","failed","timed_out","blocked"].includes(status)) return "failed";
  if (status === "manual_review") return "manual";
  return "";
}
function coveragePhaseRows(item) {
  const phases = Array.isArray(item.phase_results) ? item.phase_results : (Array.isArray(item.phases) ? item.phases : []);
  if (!phases.length) {
    return String(item.status || "").toLowerCase() === "manual_review"
      ? '<p><b>Mapped phases:</b> No automated phase is mapped; manual review is required.</p>'
      : '<p><b>Mapped phases:</b> No per-phase execution data is available for this category yet. Review the assessment report before drawing conclusions.</p>';
  }
  return '<p><b>Mapped phase execution:</b></p><div>' + phases.map(function(phase) {
    const name = phase.name || phase.code || "phase";
    const status = phase.status || "not_run";
    const checks = phase.checks == null ? "" : " · checks: " + phase.checks;
    const err = phase.error ? " · " + phase.error : "";
    return '<span class="phase-pill" title="' + coverageEscape(err) + '">' + coverageEscape(name) + ': ' + coverageEscape(coverageStatusLabel(status)) + coverageEscape(checks) + '</span>';
  }).join("") + '</div>';
}
function renderCoverage() {
  if (!coveragePayload) return;
  const sections = Array.isArray(coveragePayload.sections) ? coveragePayload.sections : [];
  const sectionFilter = el("coverageSectionFilter").value || "all";
  const statusFilter = el("coverageStatusFilter").value || "all";
  const query = (el("coverageSearch").value || "").trim().toLowerCase();
  const summary = coveragePayload.summary || {};
  const stats = [["Total areas",summary.total_areas||0],["Engine completed",summary.engines_completed||0],["Partial",summary.partial||0],["Failed / incomplete",summary.partial_or_failed||0],["Not run",summary.not_run||0],["Manual review",summary.manual_review||0]];
  el("coverageSummary").innerHTML = stats.map(function(stat) {
    return '<div class="coverage-stat"><b>' + coverageEscape(stat[1]) + '</b><span>' + coverageEscape(stat[0]) + '</span></div>';
  }).join("");
  const sectionSelect = el("coverageSectionFilter");
  const oldSelection = sectionSelect.value;
  sectionSelect.innerHTML = '<option value="all">All coverage sections</option>' + sections.map(function(section) {
    return '<option value="' + coverageEscape(section.id) + '">' + coverageEscape(section.title) + '</option>';
  }).join("");
  if (sections.some(function(section){return section.id === oldSelection;})) sectionSelect.value = oldSelection;
  let visibleCount = 0;
  const htmlSections = sections.filter(function(section) {
    return sectionSelect.value === "all" || section.id === sectionSelect.value;
  }).map(function(section) {
    const items = (section.items || []).filter(function(item) {
      const status = String(item.status || "not_run").toLowerCase();
      const matchesStatus = statusFilter === "all" || status === statusFilter ||
        (statusFilter === "partial_or_failed" && ["failed","timed_out","blocked"].includes(status)) ||
        (statusFilter === "engines_completed" && status === "completed");
      const haystack = [item.id,item.code,item.name,item.standard,item.manual,item.execution_note,item.limitation]
        .concat((item.phase_results || item.phases || []).map(function(p){return p.name + " " + p.status;})).join(" ").toLowerCase();
      return matchesStatus && (!query || haystack.includes(query));
    });
    if (!items.length) return "";
    visibleCount += items.length;
    const rows = items.map(function(item) {
      const code = item.id || item.code || "AREA";
      const name = item.name || item.title || "Unnamed coverage area";
      const status = String(item.status || "not_run").toLowerCase();
      const note = item.execution_note || item.limitation || "Review phase evidence and test prerequisites before drawing conclusions.";
      const manual = item.manual || "";
      const standard = item.standard || section.standard || "";
      return '<details class="coverage-item"><summary><span class="coverage-code">' + coverageEscape(code) + '</span><span class="coverage-name">' + coverageEscape(name) + '</span><span class="coverage-status ' + coverageStatusClass(status) + '">' + coverageEscape(coverageStatusLabel(status)) + '</span></summary><div class="coverage-detail"><p><b>Standard:</b> ' + coverageEscape(standard) + '</p>' + coveragePhaseRows(item) + '<p><b>Execution interpretation:</b> ' + coverageEscape(note) + '</p>' + (manual ? '<p><b>Manual / prerequisite gap:</b> ' + coverageEscape(manual) + '</p>' : '') + '</div></details>';
    }).join("");
    return '<section class="coverage-section"><div class="coverage-section-head"><h3>' + coverageEscape(section.title) + '</h3><span>' + items.length + ' area(s) visible</span></div>' + rows + '</section>';
  }).join("");
  el("coverageSections").innerHTML = htmlSections || '<div class="coverage-empty">No coverage areas match these filters. Change the section, status, or search text.</div>';
  const generated = coveragePayload.generated_at ? " Latest report: " + coveragePayload.generated_at + "." : " No report has been generated yet; statuses are initialized as not run.";
  el("coverageFooter").textContent = visibleCount + " coverage area(s) displayed." + generated + " Engine completion does not prove the category is secure.";
}
async function loadCoverage(force) {
  if (coverageLoading || (!force && Date.now() - coverageLastLoaded < 7000)) return;
  coverageLoading = true;
  try {
    const response = await fetch("/api/coverage?ts=" + Date.now(), {cache:"no-store",credentials:"same-origin",headers:{"Accept":"application/json"}});
    if (!response.ok) throw new Error("Coverage endpoint returned HTTP " + response.status);
    coveragePayload = await response.json();
    coverageLastLoaded = Date.now();
    renderCoverage();
  } catch (error) {
    if (!coveragePayload) el("coverageSections").innerHTML = '<div class="coverage-empty">Coverage registry could not be loaded. Refresh after reconnecting.</div>';
  } finally {
    coverageLoading = false;
  }
}

let connectionFailures = 0;
let lastGoodState = null;
let statusPollDelay = 1000;

async function poll() {
  try {
    const response = await fetch("/api/status?ts=" + Date.now(), {
      cache: "no-store",
      credentials: "same-origin",
      headers: {"Cache-Control": "no-cache", "Accept": "application/json"}
    });

    if (!response.ok) {
      throw new Error("Status endpoint returned HTTP " + response.status);
    }

    const data = await response.json();
    lastGoodState = data;
    connectionFailures = 0;
    statusPollDelay = 1000;
    renderStatus(data);
    loadCoverage(false);
  } catch (error) {
    connectionFailures += 1;
    // Preserve the latest assessment state during transient Render restarts
    // instead of replacing useful progress with a false failure state.
    if (connectionFailures >= 4) {
      el("status").textContent = "RECONNECTING";
      el("detail").textContent = "Dashboard connection interrupted. Retrying automatically; the assessment may still be running.";
      if (lastGoodState && lastGoodState.stage) el("stage").textContent = lastGoodState.stage;
    }
    statusPollDelay = Math.min(10000, 1000 * Math.pow(1.5, Math.min(connectionFailures, 6)));
  } finally {
    pollTimer = setTimeout(poll, statusPollDelay);
  }
}

document.addEventListener("DOMContentLoaded", function() {
  const button = el("startBtn");
  if (button) {
    button.addEventListener("click", startRun);
  }

  const targetInput = el("target");
  if (targetInput) {
    targetInput.addEventListener("keydown", function(event) {
      if (event.key === "Enter") {
        event.preventDefault();
        startRun();
      }
    });
  }

  ["coverageSectionFilter","coverageStatusFilter","coverageSearch"].forEach(function(id) {
    const node = el(id);
    if (node) node.addEventListener(id === "coverageSearch" ? "input" : "change", renderCoverage);
  });
  const refreshCoverage = el("refreshCoverage");
  if (refreshCoverage) refreshCoverage.addEventListener("click", function(){ loadCoverage(true); });
  loadCoverage(true);
  poll();
});
</script></body></html>"""

_HTML = _HTML.replace("__DEFAULT_TARGET__", html.escape(DEFAULT_TARGET, quote=True))

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "10000")))

