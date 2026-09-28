"""Non-destructive input stress testing for authorized web assessments.

This module fuzzes already-discovered GET/query inputs and, optionally, performs
browser-side typing checks without submitting forms. It is deliberately bounded:
same-origin only, no credential attacks, no form submission, no file upload,
no state-changing HTTP methods, and no unbounded payload generation.
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


USER_AGENT = "Sentinel-InputStress/1.0 (authorized security assessment)"

# Payloads are designed to expose parser/reflection/error-handling weaknesses,
# not to execute destructive actions.
PAYLOADS = (
    ("boundary-empty", ""),
    ("boundary-space", " "),
    ("boundary-long", "A" * 512),
    ("boundary-unicode", "Aa-123-हैलो-世界-🚀"),
    ("html-marker", "STRESS_HTML_9f31"),
    ("quote-marker", "STRESS_QUOTE_'_9f31"),
    ("jsonish", '{"stress":"9f31","value":1}'),
    ("sql-metachar", "STRESS_9f31'\\\")("),
    ("pathish", "../STRESS_9f31"),
)

ERROR_MARKERS = (
    "traceback (most recent call last)",
    "stack trace",
    "sql syntax",
    "sqlite error",
    "mysql error",
    "postgresql",
    "psycopg",
    "ora-",
    "exception in thread",
    "unhandled exception",
    "debugger",
)

class InputStressEngine:
    def __init__(self, target: str, max_urls: int = 30, max_probes: int = 180,
                 rate_rps: float | None = None, timeout: int | None = None):
        self.target = target.rstrip("/")
        parsed = urlparse(self.target)
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.netloc:
            raise ValueError("Target must be an absolute http:// or https:// URL.")
        self.origin = f"{parsed.scheme.lower()}://{parsed.netloc.lower()}"
        self.max_urls = max(1, min(int(max_urls), 100))
        self.max_probes = max(1, min(int(max_probes), 400))
        self.rate_rps = max(float(rate_rps or getattr(config, "STRESS_RATE_RPS", 3)), 0.5)
        self.timeout = int(timeout or getattr(config, "STRESS_TIMEOUT", 10))
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": USER_AGENT, "Accept": "*/*"})
        self.probes = 0
        self.last_request = 0.0
        self.checks = []
        self.findings = []

    def same_origin(self, url: str) -> bool:
        p = urlparse(url)
        return p.scheme.lower() == urlparse(self.origin).scheme.lower() and p.netloc.lower() == urlparse(self.origin).netloc.lower()

    def _request(self, url: str):
        assert_same_target(self.target, url)
        if self.probes >= self.max_probes:
            raise RuntimeError("input-stress probe budget exhausted")
        delay = (1.0 / self.rate_rps) - (time.monotonic() - self.last_request)
        if delay > 0:
            time.sleep(delay)
        response = self.session.get(url, timeout=self.timeout, allow_redirects=False, verify=True)
        self.last_request = time.monotonic()
        self.probes += 1
        return response

    def _add(self, fid, title, severity, confidence, url, detail, impact, remediation, evidence):
        self.findings.append({
            "id": fid,
            "title": title,
            "severity": severity,
            "confidence": confidence,
            "category": "Input Validation / Fuzzing",
            "method": "GET",
            "url": url,
            "detail": detail,
            "impact": impact,
            "remediation": remediation,
            "evidence": evidence,
            "owasp": "A03:2021 / WSTG-INPUT",
        })

    @staticmethod
    def fuzz_url(url: str, parameter: str, payload: str) -> str:
        parsed = urlparse(url)
        pairs = parse_qsl(parsed.query, keep_blank_values=True)
        replaced = False
        out = []
        for key, value in pairs:
            if key == parameter and not replaced:
                out.append((key, payload))
                replaced = True
            else:
                out.append((key, value))
        if not replaced:
            out.append((parameter, payload))
        return urlunparse(parsed._replace(query=urlencode(out, doseq=True)))

    def candidate_urls(self, urls):
        candidates = []
        seen = set()
        for raw in urls:
            try:
                if not self.same_origin(raw):
                    continue
                parsed = urlparse(raw)
                if parsed.query:
                    params = [k for k, _ in parse_qsl(parsed.query, keep_blank_values=True)]
                    for key in dict.fromkeys(params):
                        item = (raw, key)
                        if item not in seen:
                            seen.add(item)
                            candidates.append(item)
                else:
                    # Test a small set of common benign probe names only when
                    # the route itself was already discovered.
                    for key in ("q", "search", "query", "id"):
                        item = (raw, key)
                        if item not in seen:
                            seen.add(item)
                            candidates.append(item)
            except Exception:
                continue
            if len(candidates) >= self.max_urls * 4:
                break
        return candidates[: self.max_urls * 4]

    def run(self, urls):
        started = time.time()
        candidates = self.candidate_urls(urls)
        print(f"[STRESS] Candidate input points: {len(candidates)}", flush=True)

        for index, (base_url, parameter) in enumerate(candidates, 1):
            if self.probes >= self.max_probes:
                break
            baseline = None
            try:
                baseline = self._request(base_url)
                baseline_len = len(baseline.content)
            except (requests.RequestException, OutOfScopeError):
                continue

            for payload_name, payload in PAYLOADS:
                if self.probes >= self.max_probes:
                    break
                probe_url = self.fuzz_url(base_url, parameter, payload)
                try:
                    response = self._request(probe_url)
                except (requests.RequestException, OutOfScopeError):
                    continue

                body_lower = response.text[:500000].lower()
                reflected = payload and payload in response.text
                server_error = response.status_code >= 500
                error_marker = any(marker in body_lower for marker in ERROR_MARKERS)
                size_delta = abs(len(response.content) - baseline_len)

                check = {
                    "base_url": base_url,
                    "parameter": parameter,
                    "payload": payload_name,
                    "status": response.status_code,
                    "response_bytes": len(response.content),
                    "baseline_bytes": baseline_len,
                    "reflected": bool(reflected),
                    "server_error": server_error,
                    "error_marker": error_marker,
                    "size_delta": size_delta,
                }
                self.checks.append(check)

                if server_error:
                    self._add(
                        f"STRESS-5XX-{len(self.findings)+1:03d}",
                        "Input stress triggered a server error",
                        "Medium", "Medium", probe_url,
                        f"GET parameter '{parameter}' produced HTTP {response.status_code} with payload class '{payload_name}'.",
                        "Unexpected 5xx responses can expose fragile input handling, denial-of-service conditions, or unhandled exceptions.",
                        "Validate and constrain input server-side; return controlled 4xx responses and investigate the triggering stack path.",
                        f"status={response.status_code}; payload={payload_name}; parameter={parameter}",
                    )

                if error_marker:
                    self._add(
                        f"STRESS-ERR-{len(self.findings)+1:03d}",
                        "Input stress exposed an application error signature",
                        "Medium", "High", probe_url,
                        f"Response contained a known exception/database error signature after mutating '{parameter}'.",
                        "Error details can disclose implementation, database or framework information and help attackers refine later attacks.",
                        "Return generic production errors and keep detailed diagnostics in server-side logs.",
                        f"error_marker=True; payload={payload_name}; parameter={parameter}",
                    )

                if reflected and payload_name in {"html-marker", "quote-marker", "boundary-unicode"}:
                    self._add(
                        f"STRESS-REFLECT-{len(self.findings)+1:03d}",
                        "User-controlled input is reflected in the response",
                        "Info", "Medium", probe_url,
                        f"The stress marker for parameter '{parameter}' was reflected into the HTTP response.",
                        "Reflection is an input-flow observation; by itself it does not prove XSS. Context-sensitive output encoding must be reviewed.",
                        "Encode output according to its HTML/JS/URL context and validate the sink with a dedicated XSS test.",
                        f"reflected=True; payload={payload_name}; parameter={parameter}",
                    )

            if index % 5 == 0:
                print(f"[STRESS] input points {index}/{len(candidates)} | probes={self.probes} | findings={len(self.findings)}", flush=True)

        result = {
            "schema": "input-stress-1.0",
            "target": self.target,
            "policy": "same-origin GET fuzzing only; no form submission or state-changing requests",
            "limits": {
                "max_candidate_points": self.max_urls * 4,
                "max_probes": self.max_probes,
                "rate_rps": self.rate_rps,
                "timeout_seconds": self.timeout,
                "payload_classes": len(PAYLOADS),
            },
            "probes": self.probes,
            "checks": self.checks,
            "findings": self.findings,
            "summary": {
                "candidate_points": len(candidates),
                "probes": self.probes,
                "findings": len(self.findings),
                "by_severity": dict(Counter(x["severity"] for x in self.findings)),
            },
            "runtime_seconds": round(time.time() - started, 2),
        }
        os.makedirs(config.EVIDENCE_DIR, exist_ok=True)
        path = os.path.join(config.EVIDENCE_DIR, "input_stress.json")
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(result, handle, indent=2, ensure_ascii=False)
        return result


def run_input_stress(target: str, urls, max_urls: int = 30, max_probes: int = 180):
    return InputStressEngine(target, max_urls=max_urls, max_probes=max_probes).run(urls)
