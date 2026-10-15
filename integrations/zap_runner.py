"""Bounded, passive-first OWASP ZAP API adapter for authorized assessments."""
from __future__ import annotations
import argparse
import ipaddress
import json
import os
import sys
import time
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit
import requests


class ZapError(RuntimeError):
    pass


def origin(url: str) -> str:
    parsed = urlsplit((url or "").strip())
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("Target must be an absolute HTTP(S) URL.")
    if parsed.username or parsed.password or parsed.fragment:
        raise ValueError("Target URL must not contain credentials or a fragment.")
    host = parsed.hostname.lower()
    port = parsed.port
    default = (parsed.scheme == "http" and port in (None, 80)) or (parsed.scheme == "https" and port in (None, 443))
    if ":" in host and not host.startswith("["):
        netloc = f"[{host}]" if default else f"[{host}]:{port}"
    else:
        netloc = host if default else f"{host}:{port}"
    return urlunsplit((parsed.scheme, netloc, "", "", ""))


def validate_api_url(url: str) -> str:
    parsed = urlsplit(url)
    if parsed.scheme != "http" or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("ZAP API must be a credential-free HTTP URL on loopback.")
    host = parsed.hostname.lower()
    loopback = host == "localhost"
    try:
        loopback = loopback or ipaddress.ip_address(host).is_loopback
    except ValueError:
        pass
    if not loopback:
        raise ValueError("Refusing non-loopback ZAP API host.")
    return urlunsplit(("http", parsed.netloc, parsed.path.rstrip("/"), "", ""))


class ZapRunner:
    def __init__(self, api_url="http://127.0.0.1:8080", api_key=None, context_name=None, timeout=10, poll_interval=1, session=None):
        self.api_url = validate_api_url(api_url)
        self.context_name = context_name or os.getenv("ZAP_CONTEXT_NAME", "").strip()
        self.api_key = api_key if api_key is not None else os.getenv("ZAP_API_KEY", "")
        self.timeout = max(1.0, min(float(timeout), 30.0))
        self.poll_interval = max(0.1, min(float(poll_interval), 5.0))
        self.session = session or requests.Session()

    def _get(self, component, kind, action, params=None):
        values = dict(params or {})
        headers = {"X-ZAP-API-Key": self.api_key} if self.api_key else {}
        response = self.session.get(
            f"{self.api_url}/JSON/{component}/{kind}/{action}/",
            params=values, headers=headers, timeout=self.timeout,
        )
        response.raise_for_status()
        try:
            payload = response.json()
        except ValueError as exc:
            raise ZapError(f"ZAP returned non-JSON data for {component}/{action}.") from exc
        if not isinstance(payload, dict):
            raise ZapError(f"Unexpected ZAP response for {component}/{action}.")
        return payload

    def _poll(self, component, scan_id, deadline):
        percent = 0
        while time.monotonic() < deadline:
            payload = self._get(component, "view", "status", {"scanId": scan_id})
            try:
                percent = int(next(iter(payload.values()), "0"))
            except (TypeError, ValueError):
                percent = 0
            if percent >= 100:
                return {"status": "completed", "percent": 100}
            time.sleep(min(self.poll_interval, max(0, deadline - time.monotonic())))
        return {"status": "timed_out", "percent": percent}

    def run(self, target, *, max_seconds=300, spider=True, passive_wait=True, active=False,
            confirm_authorized=False, confirm_active=False):
        target_origin = origin(target)
        if not self.context_name:
            raise ValueError("Set ZAP_CONTEXT_NAME or pass --context-name for a reviewed ZAP context.")
        if not confirm_authorized:
            raise PermissionError("Requires --confirm-authorized.")
        if active and not confirm_active:
            raise PermissionError("Active scanning additionally requires --confirm-active-zap.")
        budget = max(10, min(int(max_seconds), 1800))
        deadline = time.monotonic() + budget
        result = {
            "schema_version": "1.0",
            "target_origin": target_origin,
            "mode": "active" if active else "passive",
            "phases": {},
            "alerts": [],
            "limitations": [
                "Alerts are observations and require manual validation.",
                "Configure and verify ZAP context/scope before testing.",
                "Active scans send attack payloads and can affect application behavior.",
                "Passive scan queue status is global to the ZAP instance.",
            ],
        }
        if spider:
            if time.monotonic() >= deadline:
                result["phases"]["spider"] = {"status": "skipped", "reason": "runtime_budget_exhausted"}
            else:
                payload = self._get("spider", "action", "scan", {"url": target.rstrip("/") + "/", "recurse": "true", "contextName": self.context_name, "subtreeOnly": "true"})
                scan_id = str(payload.get("scan", ""))
                if not scan_id:
                    raise ZapError("ZAP did not return a spider scan ID.")
                result["phases"]["spider"] = self._poll("spider", scan_id, deadline)
        if passive_wait:
            if time.monotonic() >= deadline:
                result["phases"]["passive_scan"] = {"status": "skipped", "reason": "runtime_budget_exhausted"}
            else:
                remaining = 0
                while time.monotonic() < deadline:
                    payload = self._get("pscan", "view", "recordsToScan")
                    try:
                        remaining = int(next(iter(payload.values()), "0"))
                    except (TypeError, ValueError):
                        remaining = 0
                    if remaining <= 0:
                        result["phases"]["passive_scan"] = {"status": "completed", "records_remaining": 0}
                        break
                    time.sleep(min(self.poll_interval, max(0, deadline - time.monotonic())))
                else:
                    result["phases"]["passive_scan"] = {"status": "timed_out", "records_remaining": remaining}
        if active:
            if time.monotonic() >= deadline:
                result["phases"]["active_scan"] = {"status": "skipped", "reason": "runtime_budget_exhausted"}
            else:
                payload = self._get("ascan", "action", "scan", {
                    "url": target.rstrip("/") + "/", "recurse": "true", "inScopeOnly": "true",
                })
                scan_id = str(payload.get("scan", ""))
                if not scan_id:
                    raise ZapError("ZAP did not return an active-scan ID.")
                result["phases"]["active_scan"] = self._poll("ascan", scan_id, deadline)
        payload = self._get("core", "view", "alerts", {"baseurl": target_origin, "start": "0", "count": "1000"})
        rows = payload.get("alerts", [])
        if not isinstance(rows, list):
            rows = []
        fields = ("alert", "risk", "confidence", "url", "method", "param", "attack",
                  "evidence", "description", "solution", "reference", "cweid", "wascid", "pluginId", "alertRef")
        result["alerts"] = [
            {key: row[key] for key in fields if row.get(key) not in (None, "")}
            for row in rows if isinstance(row, dict) and _same_origin(target_origin, row.get("url", ""))
        ]
        risks = ("high", "medium", "low", "informational")
        result["summary"] = {
            "alerts": len(result["alerts"]),
            "by_risk": {risk: sum(str(row.get("risk", "")).lower() == risk for row in result["alerts"]) for risk in risks},
            "phases_completed": sum(row.get("status") == "completed" for row in result["phases"].values()),
            "phases_incomplete": sum(row.get("status") != "completed" for row in result["phases"].values()),
        }
        return result


def _same_origin(expected, url):
    try:
        return origin(url) == expected
    except (TypeError, ValueError):
        return False


def main(argv=None):
    parser = argparse.ArgumentParser(description="Bounded OWASP ZAP integration for authorized assessments")
    parser.add_argument("--target", required=True)
    parser.add_argument("--zap-api", default=os.getenv("ZAP_API_URL", "http://127.0.0.1:8080"))
    parser.add_argument("--context-name", default=os.getenv("ZAP_CONTEXT_NAME", ""), help="Reviewed ZAP context name; required for scope control")
    parser.add_argument("--output", default="reports/zap_report.json")
    parser.add_argument("--max-seconds", type=int, default=300)
    parser.add_argument("--no-spider", action="store_true")
    parser.add_argument("--no-passive-wait", action="store_true")
    parser.add_argument("--active", action="store_true", help="Enable active attack scanning")
    parser.add_argument("--confirm-authorized", action="store_true")
    parser.add_argument("--confirm-active-zap", action="store_true")
    args = parser.parse_args(argv)
    try:
        runner = ZapRunner(api_url=args.zap_api, context_name=args.context_name)
        report = runner.run(args.target, max_seconds=args.max_seconds, spider=not args.no_spider,
            passive_wait=not args.no_passive_wait, active=args.active,
            confirm_authorized=args.confirm_authorized, confirm_active=args.confirm_active_zap)
        path = Path(args.output)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        print(json.dumps({"output": str(path), "summary": report["summary"], "phases": report["phases"]}, indent=2))
        return 0 if report["summary"]["phases_incomplete"] == 0 else 2
    except (ValueError, PermissionError, ZapError, requests.RequestException) as exc:
        print(f"[ZAP ERROR] {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
