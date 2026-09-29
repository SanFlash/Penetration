"""Controlled aggressive read-only testing for authorized web assessments.

Phase 3 increases adversarial coverage without state changes:
- same-origin GET only
- bounded payload and duplicate-parameter mutations
- malformed/encoded query values
- harmless request-header variations
- response-differential checks
- strict request/probe/rate/time budgets
- no form submission, uploads, authentication attacks, or destructive methods
"""

from __future__ import annotations

import json
import os
import time
from collections import Counter
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

import requests

import config
from utils.scope import assert_same_target, OutOfScopeError


USER_AGENT = "Sentinel-Phase3-AggressiveReadOnly/1.0"

PAYLOADS = (
    ("empty", ""),
    ("space", " "),
    ("long-512", "A" * 512),
    ("xlong-2048", "B" * 2048),
    ("unicode", "Aa-123-हैलो-世界-🚀"),
    ("quotes", "STRESS_'\")("),
    ("html-marker", "STRESS_HTML_p3"),
    ("jsonish", '{"phase3":"probe","n":1}'),
    ("pathish", "../STRESS_P3"),
    ("encoded", "%2e%2e%2fSTRESS_P3"),
    ("delimiter", "STRESS_P3&=;|,:"),
)

HEADER_VARIANTS = (
    ("baseline", {}),
    ("accept-json", {"Accept": "application/json"}),
    ("accept-html", {"Accept": "text/html"}),
    ("no-cache", {"Cache-Control": "no-cache"}),
)

ERROR_MARKERS = (
    "traceback (most recent call last)",
    "stack trace",
    "sql syntax",
    "sqlite error",
    "mysql error",
    "postgresql",
    "psycopg",
    "unhandled exception",
    "debugger",
)


class AggressiveReadonlyEngine:
    def __init__(self, target: str, max_urls: int = 30, max_probes: int = 220,
                 rate_rps: float | None = None, timeout: int | None = None,
                 max_runtime: int = 180):
        self.target = target.rstrip("/")
        parsed = urlparse(self.target)
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.netloc:
            raise ValueError("Target must be an absolute http:// or https:// URL.")
        self.origin = f"{parsed.scheme.lower()}://{parsed.netloc.lower()}"
        self.max_urls = max(1, min(int(max_urls), 60))
        self.max_probes = max(1, min(int(max_probes), 400))
        self.rate_rps = max(float(rate_rps or 2), 0.5)
        self.timeout = max(1, min(int(timeout or 10), 30))
        self.max_runtime = max(10, min(int(max_runtime), 600))
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": USER_AGENT, "Accept": "*/*"})
        self.probes = 0
        self.last_request = 0.0
        self.started = 0.0
        self.checks = []
        self.findings = []

    def same_origin(self, url: str) -> bool:
        p = urlparse(url)
        return (
            p.scheme.lower() == urlparse(self.origin).scheme.lower()
            and p.netloc.lower() == urlparse(self.origin).netloc.lower()
        )

    def _budget_ok(self):
        return self.probes < self.max_probes and (time.monotonic() - self.started) < self.max_runtime

    def _request(self, url: str, headers: dict | None = None):
        assert_same_target(self.target, url)
        if not self._budget_ok():
            raise RuntimeError("phase3 probe/runtime budget exhausted")
        delay = (1.0 / self.rate_rps) - (time.monotonic() - self.last_request)
        if delay > 0:
            time.sleep(delay)
        response = self.session.get(
            url, headers=headers or {}, timeout=self.timeout,
            allow_redirects=False, verify=True
        )
        self.last_request = time.monotonic()
        self.probes += 1
        return response

    @staticmethod
    def mutate_query(url: str, parameter: str, value: str, duplicate: bool = False) -> str:
        parsed = urlparse(url)
        pairs = parse_qsl(parsed.query, keep_blank_values=True)
        out = []
        replaced = False
        for key, current in pairs:
            if key == parameter and not replaced:
                out.append((key, value))
                if duplicate:
                    out.append((key, current))
                replaced = True
            else:
                out.append((key, current))
        if not replaced:
            out.append((parameter, value))
        return urlunparse(parsed._replace(query=urlencode(out, doseq=True)))

    def candidates(self, urls):
        result = []
        seen = set()
        for raw in urls:
            if len(result) >= self.max_urls:
                break
            try:
                if not self.same_origin(raw):
                    continue
                parsed = urlparse(raw)
                params = (
                    list(dict.fromkeys(k for k, _ in parse_qsl(parsed.query, keep_blank_values=True)))
                    if parsed.query else ["q"]
                )
                for parameter in params[:3]:
                    item = (raw, parameter)
                    if item not in seen:
                        seen.add(item)
                        result.append(item)
                    if len(result) >= self.max_urls:
                        break
            except Exception:
                continue
        return result

    def _finding(self, fid, title, severity, confidence, url, detail, impact, remediation, evidence):
        self.findings.append({
            "id": fid, "title": title, "severity": severity, "confidence": confidence,
            "category": "Phase 3 / Aggressive Read-Only", "method": "GET", "url": url,
            "detail": detail, "impact": impact, "remediation": remediation,
            "evidence": evidence, "owasp": "WSTG-INPUT / WSTG-ERRH",
        })

    def run(self, urls):
        self.started = time.monotonic()
        candidates = self.candidates(urls)
        print(f"[PHASE3] Candidate input points: {len(candidates)}", flush=True)

        for index, (base_url, parameter) in enumerate(candidates, 1):
            if not self._budget_ok():
                break
            try:
                baseline = self._request(base_url)
            except (requests.RequestException, OutOfScopeError):
                continue

            baseline_len = len(baseline.content)
            baseline_status = baseline.status_code

            for payload_name, payload in PAYLOADS:
                if not self._budget_ok():
                    break
                probe_url = self.mutate_query(base_url, parameter, payload)
                try:
                    response = self._request(probe_url)
                except (requests.RequestException, OutOfScopeError):
                    continue
                body = response.text[:500000].lower()
                error_marker = any(marker in body for marker in ERROR_MARKERS)
                self.checks.append({
                    "kind": "payload", "base_url": base_url, "parameter": parameter,
                    "payload": payload_name, "status": response.status_code,
                    "baseline_status": baseline_status,
                    "response_bytes": len(response.content), "baseline_bytes": baseline_len,
                    "size_delta": abs(len(response.content) - baseline_len),
                    "error_marker": error_marker,
                })

                if response.status_code >= 500:
                    self._finding(
                        f"P3-5XX-{len(self.findings)+1:03d}",
                        "Bounded input mutation triggered a server error",
                        "Medium", "Medium", probe_url,
                        f"Parameter '{parameter}' returned HTTP {response.status_code} for payload class '{payload_name}'.",
                        "Unexpected server errors can indicate fragile input handling or unhandled exceptions.",
                        "Validate inputs server-side and return controlled 4xx responses; inspect server logs for the triggering path.",
                        f"status={response.status_code}; payload={payload_name}; parameter={parameter}",
                    )
                elif error_marker:
                    self._finding(
                        f"P3-ERR-{len(self.findings)+1:03d}",
                        "Bounded input mutation exposed an error signature",
                        "Medium", "High", probe_url,
                        f"Known exception/database error text appeared after mutating '{parameter}'.",
                        "Detailed error responses can disclose implementation details and aid later attack refinement.",
                        "Return generic production errors and retain detailed diagnostics only in server-side logs.",
                        f"error_marker=True; payload={payload_name}; parameter={parameter}",
                    )

            if self._budget_ok():
                duplicate_url = self.mutate_query(base_url, parameter, "P3_DUPLICATE", duplicate=True)
                try:
                    response = self._request(duplicate_url)
                    self.checks.append({
                        "kind": "duplicate-parameter", "base_url": base_url,
                        "parameter": parameter, "status": response.status_code,
                        "response_bytes": len(response.content),
                        "baseline_status": baseline_status, "baseline_bytes": baseline_len,
                    })
                    if response.status_code >= 500:
                        self._finding(
                            f"P3-DUP-5XX-{len(self.findings)+1:03d}",
                            "Duplicate query parameter triggered a server error",
                            "Medium", "Medium", duplicate_url,
                            f"Duplicate '{parameter}' parameters returned HTTP {response.status_code}.",
                            "Parser disagreement across layers can create validation or authorization inconsistencies.",
                            "Define deterministic duplicate-parameter handling and validate after canonicalization.",
                            f"status={response.status_code}; parameter={parameter}",
                        )
                except (requests.RequestException, OutOfScopeError):
                    pass

            for variant_name, headers in HEADER_VARIANTS[1:]:
                if not self._budget_ok():
                    break
                try:
                    response = self._request(base_url, headers=headers)
                except (requests.RequestException, OutOfScopeError):
                    continue
                self.checks.append({
                    "kind": "header-variant", "base_url": base_url,
                    "variant": variant_name, "status": response.status_code,
                    "response_bytes": len(response.content),
                    "baseline_status": baseline_status, "baseline_bytes": baseline_len,
                })
                if response.status_code >= 500:
                    self._finding(
                        f"P3-HDR-5XX-{len(self.findings)+1:03d}",
                        "Harmless request-header variation triggered a server error",
                        "Low", "Medium", base_url,
                        f"Header variant '{variant_name}' returned HTTP {response.status_code}.",
                        "Content-negotiation or middleware inconsistencies can expose fragile request handling.",
                        "Normalize and validate request headers before application routing; return controlled errors.",
                        f"variant={variant_name}; status={response.status_code}",
                    )

            if index % 5 == 0:
                print(
                    f"[PHASE3] input points {index}/{len(candidates)} | "
                    f"probes={self.probes} | findings={len(self.findings)}",
                    flush=True,
                )

        result = {
            "schema": "phase3-aggressive-readonly-1.0",
            "target": self.target,
            "policy": "same-origin GET only; bounded payloads and harmless header/duplicate parameter variations; no form submission or state changes",
            "limits": {
                "max_candidate_points": self.max_urls, "max_probes": self.max_probes,
                "rate_rps": self.rate_rps, "timeout_seconds": self.timeout,
                "max_runtime_seconds": self.max_runtime, "payload_classes": len(PAYLOADS),
            },
            "probes": self.probes, "checks": self.checks, "findings": self.findings,
            "summary": {
                "candidate_points": len(candidates), "payload_classes": len(PAYLOADS),
                "probes": self.probes, "findings": len(self.findings),
                "by_severity": dict(Counter(x["severity"] for x in self.findings)),
            },
            "runtime_seconds": round(time.monotonic() - self.started, 2),
        }
        os.makedirs(config.EVIDENCE_DIR, exist_ok=True)
        with open(os.path.join(config.EVIDENCE_DIR, "phase3_aggressive_readonly.json"), "w", encoding="utf-8") as handle:
            json.dump(result, handle, indent=2, ensure_ascii=False)
        return result


def run_aggressive_readonly(target: str, urls, max_urls: int = 30, max_probes: int = 220):
    return AggressiveReadonlyEngine(target, max_urls=max_urls, max_probes=max_probes).run(urls)
