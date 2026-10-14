"""Optional OWASP ZAP passive baseline integration.

Requires a separately managed ZAP daemon, API key, and a ZAP context already
restricted to the authorized target. This integration does not launch active
scanning, fuzzing, forced browsing, or state-changing requests.
"""
from __future__ import annotations

import json
import os
import time
from urllib.parse import urlparse

import requests

import config
from reports.report_generator import generate


def _origin(url: str) -> str:
    parsed = urlparse(url)
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.netloc:
        raise ValueError("Target must be an absolute HTTP(S) URL.")
    return f"{parsed.scheme.lower()}://{parsed.netloc.lower()}"


def _api_get(session, base, api_key, path, params=None, timeout=10):
    values = dict(params or {})
    values["apikey"] = api_key
    response = session.get(base.rstrip("/") + path, params=values, timeout=timeout)
    response.raise_for_status()
    payload = response.json()
    if not isinstance(payload, dict):
        raise RuntimeError("ZAP API returned an unexpected response.")
    return payload


def run_zap_baseline(target: str, state=None, max_runtime_seconds: int = 240) -> int:
    """Run ZAP spider + passive scan only and emit Sentinel's standard report."""
    started = time.monotonic()
    origin = _origin(target)
    api_base = os.getenv("SENTINEL_ZAP_API_URL", "").strip().rstrip("/")
    api_key = os.getenv("SENTINEL_ZAP_API_KEY", "").strip()
    context_name = os.getenv("SENTINEL_ZAP_CONTEXT", "").strip()
    phases = {}
    findings = []
    errors = []
    completed = False

    def update(stage, detail, progress, status="RUNNING"):
        if state is not None:
            state.update(stage=stage, detail=detail, progress=progress, status=status)

    if not api_base or not api_key or not context_name:
        reason = (
            "ZAP baseline was not run. Configure SENTINEL_ZAP_API_URL, "
            "SENTINEL_ZAP_API_KEY, and SENTINEL_ZAP_CONTEXT; the named ZAP context "
            "must restrict spider scope to the authorized target origin."
        )
        phases["zap_baseline"] = {"status": "not_run", "checks": 0, "error": reason}
        metadata = {
            "profile": "zap", "status": "PARTIAL", "phase_status": phases,
            "phase_failures": ["zap_baseline"], "runtime_seconds": 0,
            "scope_policy": "ZAP passive baseline only; requires pre-scoped ZAP context",
        }
        generate(target, findings, config.EVIDENCE_DIR, out_dir=config.REPORT_DIR, metadata=metadata)
        update("ZAP BASELINE NOT CONFIGURED", reason, 100, "PARTIAL")
        return 1

    session = requests.Session()
    session.headers.update({"User-Agent": "Sentinel-ZAP-Baseline/1.0"})
    deadline = started + max(30, min(int(max_runtime_seconds), 300))
    probes = 0
    try:
        update("ZAP PREFLIGHT", "Checking the configured ZAP API and scope context.", 5)
        version = _api_get(session, api_base, api_key, "/JSON/core/view/version/")
        if not version.get("version"):
            raise RuntimeError("ZAP API version check returned no version.")
        contexts = _api_get(session, api_base, api_key, "/JSON/context/view/contextList/")
        context_names = contexts.get("contextList") or []
        if context_name not in context_names:
            raise RuntimeError(f"Configured ZAP context '{context_name}' was not found. No target scan was started.")

        # Require the configured context's inclusion regexes to contain the exact origin.
        regexes = _api_get(
            session, api_base, api_key, "/JSON/context/view/includeRegexs/",
            {"contextName": context_name},
        ).get("regexes") or []
        if not regexes:
            raise RuntimeError("The configured ZAP context has no inclusion regex. Add an exact target-origin scope before scanning.")
        if not any(origin in str(regex) for regex in regexes):
            raise RuntimeError("The configured ZAP context inclusion rules do not visibly include the exact target origin. No scan was started.")

        update("ZAP SPIDER", f"Starting passive-baseline spider in pre-scoped context '{context_name}'.", 12)
        scan = _api_get(
            session, api_base, api_key, "/JSON/spider/action/scan/",
            {"url": target.rstrip("/") + "/", "contextName": context_name,
             "subtreeOnly": "true", "recurse": "true", "maxDuration": "3"},
        )
        scan_id = str(scan.get("scan", ""))
        if not scan_id.isdigit():
            raise RuntimeError("ZAP did not return a valid spider scan identifier.")
        spider_done = False
        while time.monotonic() < deadline:
            status = _api_get(session, api_base, api_key, "/JSON/spider/view/status/", {"scanId": scan_id})
            probes += 1
            percent = int(status.get("status", 0))
            update("ZAP SPIDER", f"Spider progress: {percent}%.", min(55, 15 + int(percent * 0.4)))
            if percent >= 100:
                spider_done = True
                break
            time.sleep(1.5)
        phases["zap_spider"] = {"status": "completed" if spider_done else "timed_out", "checks": probes}
        if not spider_done:
            errors.append("Spider did not finish within the configured runtime budget.")

        passive_done = False
        while time.monotonic() < deadline:
            queue = _api_get(session, api_base, api_key, "/JSON/pscan/view/recordsToScan/")
            probes += 1
            remaining = int(queue.get("recordsToScan", 0))
            update("ZAP PASSIVE SCAN", f"Passive records remaining: {remaining}. Active scan is disabled.", min(85, 60 + (5 if remaining == 0 else 0)))
            if remaining <= 0:
                passive_done = True
                break
            time.sleep(1.5)
        phases["zap_passive"] = {"status": "completed" if passive_done else "timed_out", "checks": probes}
        if not passive_done:
            errors.append("Passive scanner queue did not drain before the runtime deadline.")

        update("ZAP ALERT COLLECTION", "Collecting alerts for the requested target origin.", 88)
        alerts_payload = _api_get(
            session, api_base, api_key, "/JSON/alert/view/alerts/",
            {"baseurl": origin, "start": "0", "count": "500"},
        )
        alerts = alerts_payload.get("alerts") or []
        for index, alert in enumerate(alerts, 1):
            alert_url = str(alert.get("url", ""))
            try:
                if _origin(alert_url) != origin:
                    continue
            except ValueError:
                continue
            risk = str(alert.get("risk", "Informational")).lower()
            severity = {"high": "High", "medium": "Medium", "low": "Low", "informational": "Info"}.get(risk, "Info")
            findings.append({
                "id": f"ZAP-{str(alert.get('pluginId', 'ALERT'))}-{index:04d}",
                "title": str(alert.get("alert", "OWASP ZAP alert"))[:240],
                "severity": severity,
                "confidence": str(alert.get("confidence", "Medium")).title(),
                "category": "OWASP ZAP Baseline",
                "url": alert_url,
                "method": str(alert.get("method", "GET")),
                "evidence": str(alert.get("evidence", ""))[:1200],
                "detail": str(alert.get("description", ""))[:4000],
                "impact": str(alert.get("other", ""))[:2000],
                "remediation": str(alert.get("solution", ""))[:3000],
                "reference": str(alert.get("reference", ""))[:2000],
                "cwe": str(alert.get("cweid", "")),
                "wasc": str(alert.get("wascid", "")),
                "scanner": "OWASP ZAP",
            })
        phases["zap_alert_collection"] = {"status": "completed", "checks": len(alerts), "findings": len(findings)}
        completed = spider_done and passive_done
    except Exception as exc:
        errors.append(f"{type(exc).__name__}: {exc}")
        phases.setdefault("zap_baseline", {"status": "failed", "checks": probes, "error": str(exc)})
    finally:
        session.close()

    elapsed = round(time.monotonic() - started, 2)
    overall = "COMPLETE" if completed and not errors else "PARTIAL"
    metadata = {
        "profile": "zap", "status": overall, "phase_status": phases,
        "phase_failures": [name for name, row in phases.items() if row.get("status") not in {"completed", "not_run"}],
        "runtime_seconds": elapsed,
        "zap": {"integration": "external ZAP API", "version": locals().get("version", {}).get("version", "unknown"),
                "mode": "spider + passive scanner; active scan disabled", "alerts_returned": len(findings),
                "errors": errors, "scope_origin": origin},
        "scope_policy": "exact target origin; pre-scoped ZAP context required; active scanning disabled",
    }
    os.makedirs(config.EVIDENCE_DIR, exist_ok=True)
    with open(os.path.join(config.EVIDENCE_DIR, "zap_baseline.json"), "w", encoding="utf-8") as handle:
        json.dump({"target": origin, "metadata": metadata, "phases": phases, "alerts": findings}, handle, indent=2)
    generate(target, findings, config.EVIDENCE_DIR, out_dir=config.REPORT_DIR, metadata=metadata)
    update("ZAP BASELINE FINISHED", f"ZAP baseline {overall.lower()}; {len(findings)} alerts; runtime {elapsed}s. Active scan was not run.", 100, overall)
    return 0 if overall == "COMPLETE" else 1
