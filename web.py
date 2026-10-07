"""Hosted Sentinel web console for Render.

The CLI remains the source of truth for the assessment engine. This module adds
an HTTP control plane so the framework can be run from a browser on Render.
All API routes except /healthz require SENTINEL_ACCESS_TOKEN when configured.
"""
from __future__ import annotations

import html
import os
import threading
import time
from pathlib import Path

from flask import Flask, jsonify, request, send_from_directory

import config
from main import run_pentest_profile
from ui.dashboard import DashboardState

app = Flask(__name__)

ACCESS_TOKEN = os.getenv("SENTINEL_ACCESS_TOKEN", "").strip()
DEFAULT_TARGET = os.getenv("SENTINEL_DEFAULT_TARGET", "").strip() or config.PENTEST_TARGET_ORIGIN

_run_lock = threading.Lock()
_run_thread = None
_state = DashboardState(target=DEFAULT_TARGET, profile="pentest")
_last_result = None
_last_error = None


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


def _worker(target: str):
    global _last_result, _last_error
    _last_error = None
    try:
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
                stage="PENTEST COMPLETE",
                detail="Assessment and evidence are ready.",
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


@app.get("/api/status")
def status():
    auth = _require_auth()
    if auth:
        return auth
    payload = _state.snapshot()
    payload["running"] = _run_lock.locked()
    payload["last_result"] = _last_result
    payload["last_error"] = _last_error
    payload["reports"] = {
        "html": "/reports/report.html",
        "portable_html": "/reports/report_portable.html",
        "pdf": "/reports/report.pdf",
        "xlsx": "/reports/penetration_report.xlsx",
        "findings_json": "/reports/findings.json",
        "manifest": "/reports/evidence_manifest.json",
    }
    return jsonify(payload)


@app.post("/api/run")
def run():
    global _run_thread, _state, _last_result
    auth = _require_auth()
    if auth:
        return auth

    if not _run_lock.acquire(blocking=False):
        return jsonify({"error": "assessment_already_running"}), 409

    body = request.get_json(silent=True) or {}
    target = str(body.get("target") or DEFAULT_TARGET).strip().rstrip("/")
    authorized = bool(body.get("authorized", False))

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

    _state = DashboardState(target=target, profile="pentest")
    _state.update(
        status="RUNNING",
        stage="QUEUED",
        detail="Assessment worker starting...",
        progress=0,
    )
    _last_result = None

    _run_thread = threading.Thread(target=_worker, args=(target,), daemon=True)
    _run_thread.start()
    return jsonify({"accepted": True, "target": target}), 202


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
    # HTML/JSON response hide the newest findings or evidence links.
    if base in {Path(config.REPORT_DIR).resolve(), Path(config.EVIDENCE_DIR).resolve()}:
        # Reports and screenshots are regenerated between runs. Do not let a
        # browser or proxy keep an older HTML/image asset after a new scan.
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        response.headers["Pragma"] = "no-cache"
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
*{box-sizing:border-box}body{margin:0;background:radial-gradient(circle at 50% 0,#123047 0,#04070d 45%,#020307 100%);color:var(--text);font:14px/1.5 Inter,Segoe UI,Arial,sans-serif;min-height:100vh}.wrap{max-width:1250px;margin:auto;padding:22px}.top{display:flex;justify-content:space-between;gap:16px;align-items:center;margin-bottom:16px}.brand{font-weight:900;letter-spacing:.12em}.badge{border:1px solid var(--line);border-radius:999px;padding:7px 12px;color:var(--green);background:#06150f}.grid{display:grid;grid-template-columns:1.4fr .6fr;gap:14px}.panel{background:#07101bf2;border:1px solid var(--line);border-radius:16px;box-shadow:0 18px 70px #0008;overflow:hidden}.pad{padding:18px}h2,h3{margin-top:0}.muted{color:var(--muted)}label{display:block;color:var(--muted);font-size:12px;margin:12px 0 6px;text-transform:uppercase;letter-spacing:.08em}input{width:100%;padding:12px;border:1px solid var(--line);border-radius:10px;background:#03070d;color:var(--text)}button{margin-top:14px;width:100%;padding:12px;border:0;border-radius:10px;background:linear-gradient(90deg,var(--blue),var(--green));color:#02100b;font-weight:900;cursor:pointer}.hero{min-height:390px;position:relative;display:flex;align-items:center;justify-content:center;text-align:center}.ring{width:210px;height:210px;border:1px solid #38e8a066;border-radius:50%;box-shadow:0 0 70px #38e8a01a,inset 0 0 50px #38e8a01a;animation:pulse 2.2s ease-in-out infinite}.core{position:absolute;width:72px;height:72px;border-radius:50%;border:1px solid var(--green);box-shadow:0 0 45px #38e8a055;background:#38e8a014}.center{position:absolute;padding:0 30px}.stage{font-size:20px;font-weight:900;letter-spacing:.08em;margin-top:18px}.detail{color:var(--muted);margin-top:6px}@keyframes pulse{50%{transform:scale(1.08);opacity:.72}}.bar{height:9px;background:#101b29;border-radius:99px;overflow:hidden;margin:10px 0}.fill{height:100%;width:0;background:linear-gradient(90deg,var(--blue),var(--green));transition:width .35s}.metrics{display:grid;grid-template-columns:repeat(4,1fr);gap:8px}.metric{border:1px solid var(--line);border-radius:10px;padding:10px;background:#08121e}.metric b{display:block;font-size:21px}.metric span{color:var(--muted);font-size:10px;text-transform:uppercase}.links{display:grid;gap:8px;margin-top:14px}.links a{color:var(--green);text-decoration:none;border:1px solid var(--line);padding:9px;border-radius:9px}.logs{margin-top:14px;height:220px;overflow:auto;background:#02050a;border-top:1px solid var(--line);padding:12px;font:12px/1.6 Consolas,monospace}.ok{color:var(--green)}.err{color:var(--red)}.warn{color:var(--yellow)}@media(max-width:900px){.grid{grid-template-columns:1fr}.metrics{grid-template-columns:repeat(2,1fr)}.wrap{padding:12px}}
</style></head>
<body><main class="wrap">
<header class="top"><div class="brand">SENTINEL // HOSTED PENTEST CONSOLE</div><div id="status" class="badge">IDLE</div></header>
<div class="grid">
<section class="panel hero"><div class="ring"></div><div class="core"></div><div class="center"><div class="stage" id="stage">READY</div><div class="detail" id="detail">Start an authorized assessment.</div></div></section>
<aside class="panel pad"><h3>Start Assessment</h3>
<div class="muted">Step 1 — enter the web URL. Nothing is scanned until you submit it.</div>
<label>Web URL</label><input id="target" value="__DEFAULT_TARGET__" placeholder="https://example.com" autocomplete="url" inputmode="url">
<label style="display:flex;gap:9px;align-items:flex-start;text-transform:none;letter-spacing:0;font-size:12px;color:var(--text);margin-top:14px"><input id="authorized" type="checkbox" style="width:auto;margin-top:2px"> <span>I confirm I own this website or have explicit permission to perform security testing against it.</span></label>
<button id="startBtn" type="button">START PENTEST</button>
<div class="metrics" style="margin-top:14px"><div class="metric"><b id="pages">0</b><span>pages</span></div><div class="metric"><b id="checks">0</b><span>checks</span></div><div class="metric"><b id="findings">0</b><span>findings</span></div><div class="metric"><b id="errors">0</b><span>errors</span></div></div>
<div style="margin-top:18px"><div id="pct">0%</div><div class="bar"><div id="fill" class="fill"></div></div></div>
<div class="links"><a id="reportLink" href="/reports/report.html" target="_blank">Open live HTML report</a><a href="/reports/report_portable.html" target="_blank">Portable report</a><a href="/reports/findings.json" target="_blank">Findings JSON</a><a href="/reports/evidence_manifest.json" target="_blank">Evidence manifest</a><a href="/reports/report.pdf" target="_blank">PDF report</a><a href="/reports/penetration_report.xlsx" target="_blank">XLSX report</a></div><div id="reportNotice" class="muted" style="margin-top:10px">The HTML report is refreshed during the assessment and preserves partial evidence if a later phase fails.</div>
</aside></div>
<section class="panel" style="margin-top:14px"><div class="pad"><h3>Live execution log</h3></div><div id="logs" class="logs"></div></section>
</main>
<script>
const el = (id) => document.getElementById(id);
let pollTimer = null;

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
    const timeout = setTimeout(() => controller.abort(), 15000);

    const response = await fetch("/api/run?ts=" + Date.now(), {
      method: "POST",
      cache: "no-store",
      headers: {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Cache-Control": "no-cache"
      },
      body: JSON.stringify({ target: target, authorized: true }),
      signal: controller.signal
    });

    clearTimeout(timeout);

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

    showState("RUNNING", "QUEUED", "Assessment accepted. The pentest engine is starting.");
    setButton(true, "PENTEST RUNNING");
  } catch (error) {
    const message = error && error.name === "AbortError"
      ? "The server did not respond within 15 seconds."
      : (error && error.message ? error.message : "Unable to start the assessment.");

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
  if (reportNotice) {
    if (running) reportNotice.textContent = "Live report is being refreshed as phases finish. You can open it while the assessment is running.";
    else if (s.status === "FAILED") reportNotice.textContent = "The assessment stopped, but the partial HTML report and evidence have been preserved for review.";
    else if (s.status === "COMPLETE") reportNotice.textContent = "Assessment complete. Opening the HTML report with preserved evidence...";
    else reportNotice.textContent = "The HTML report is refreshed during the assessment and preserves partial evidence if a later phase fails.";
  }

  if (s.status === "COMPLETE" && !window.__sentinelReportOpened) {
    window.__sentinelReportOpened = true;
    const reportUrl = (s.reports && s.reports.html ? s.reports.html : "/reports/report.html") + "?ts=" + Date.now();
    setTimeout(function() {
      try {
        window.location.href = reportUrl;
      } catch (_) {
        window.open(reportUrl, "_blank", "noopener");
      }
    }, 250);
  }
  if (running) {
    setButton(true, "PENTEST RUNNING");
  } else {
    setButton(false, "START PENTEST");
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

async function poll() {
  try {
    const response = await fetch("/api/status?ts=" + Date.now(), {
      cache: "no-store",
      headers: {"Cache-Control": "no-cache"}
    });

    if (!response.ok) {
      throw new Error("Status endpoint returned HTTP " + response.status);
    }

    const data = await response.json();
    renderStatus(data);
  } catch (error) {
    showState("ERROR", "STATUS CONNECTION FAILED",
      error && error.message ? error.message : "Cannot reach the status endpoint.");
  } finally {
    pollTimer = setTimeout(poll, 1000);
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

  poll();
});
</script></body></html>"""

_HTML = _HTML.replace("__DEFAULT_TARGET__", html.escape(DEFAULT_TARGET, quote=True))

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "10000")))

