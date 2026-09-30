"""Bounded valid/invalid input-validation assessment for authorized targets.

GET-only. It compares a baseline value with type-oriented valid and invalid
values on already-discovered query parameters. It never submits forms or uses
state-changing HTTP methods.
"""

from __future__ import annotations

import json
import os
import re
import time
from collections import Counter
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

import requests

import config
from utils.scope import assert_same_target, OutOfScopeError

USER_AGENT = "Sentinel-InputValidation/1.0 (authorized security assessment)"

PROFILES = {
    "numeric": {"valid": "123", "invalid": ("-1", "abc", "1.5", "999999999999999999999999")},
    "email": {"valid": "qa@example.test", "invalid": ("not-an-email", "qa@", "@example.test", "qa example.test")},
    "boolean": {"valid": "true", "invalid": ("maybe", "truthy", "2", "")},
    "date": {"valid": "2026-09-30", "invalid": ("2026-99-99", "30-09-2026", "not-a-date", "0000-00-00")},
    "identifier": {"valid": "123", "invalid": ("abc", "../123", "%00", "1/2")},
    "text": {"valid": "test-value", "invalid": ("", " ", "A" * 1024, "\x00\x01\x02")},
}

NUMERIC_NAMES = re.compile(r"(id|count|page|limit|offset|age|year|price|amount|number|qty|quantity)", re.I)
EMAIL_NAMES = re.compile(r"(email|e-mail)", re.I)
BOOLEAN_NAMES = re.compile(r"(active|enabled|verified|published|visible|admin|is_)", re.I)
DATE_NAMES = re.compile(r"(date|day|month|year|from|to|start|end)", re.I)
IDENTIFIER_NAMES = re.compile(r"(uuid|user_id|order_id|product_id|account_id|slug)", re.I)


def classify_parameter(name: str) -> str:
    if EMAIL_NAMES.search(name):
        return "email"
    if BOOLEAN_NAMES.search(name):
        return "boolean"
    if DATE_NAMES.search(name):
        return "date"
    if IDENTIFIER_NAMES.search(name):
        return "identifier"
    if NUMERIC_NAMES.search(name):
        return "numeric"
    return "text"


class InputValidationEngine:
    def __init__(self, target: str, max_urls: int = 30, max_probes: int = 180,
                 rate_rps: float | None = None, timeout: int | None = None):
        self.target = target.rstrip("/")
        parsed = urlparse(self.target)
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.netloc:
            raise ValueError("Target must be an absolute http:// or https:// URL.")
        self.max_urls = max(1, min(int(max_urls), 80))
        self.max_probes = max(1, min(int(max_probes), 300))
        self.rate_rps = max(float(rate_rps or getattr(config, "VALIDATION_RATE_RPS", 3)), 0.5)
        self.timeout = int(timeout or getattr(config, "VALIDATION_TIMEOUT", 10))
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": USER_AGENT, "Accept": "*/*"})
        self.probes = 0
        self.last_request = 0.0
        self.checks = []
        self.findings = []

    def _request(self, url: str):
        assert_same_target(self.target, url)
        if self.probes >= self.max_probes:
            raise RuntimeError("input-validation probe budget exhausted")
        delay = (1.0 / self.rate_rps) - (time.monotonic() - self.last_request)
        if delay > 0:
            time.sleep(delay)
        response = self.session.get(url, timeout=self.timeout, allow_redirects=False, verify=True)
        self.last_request = time.monotonic()
        self.probes += 1
        return response

    @staticmethod
    def mutate(url: str, parameter: str, value: str) -> str:
        parsed = urlparse(url)
        pairs = parse_qsl(parsed.query, keep_blank_values=True)
        out = []
        replaced = False
        for key, old in pairs:
            if key == parameter and not replaced:
                out.append((key, value))
                replaced = True
            else:
                out.append((key, old))
        if not replaced:
            out.append((parameter, value))
        return urlunparse(parsed._replace(query=urlencode(out, doseq=True)))

    def candidate_points(self, urls):
        points = []
        seen = set()
        for raw in urls:
            try:
                if urlparse(raw).query == "":
                    continue
                parsed = urlparse(raw)
                if not (parsed.scheme and parsed.netloc):
                    continue
                for key, _ in parse_qsl(parsed.query, keep_blank_values=True):
                    item = (raw, key)
                    if item not in seen:
                        seen.add(item)
                        points.append(item)
            except Exception:
                continue
            if len(points) >= self.max_urls:
                break
        return points[:self.max_urls]

    @staticmethod
    def _error_signature(response) -> bool:
        body = response.text[:500000].lower()
        markers = (
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
        return any(marker in body for marker in markers)

    def _finding(self, fid, title, severity, confidence, url, detail, impact, remediation, evidence):
        self.findings.append({
            "id": fid,
            "title": title,
            "severity": severity,
            "confidence": confidence,
            "category": "Input Validation",
            "method": "GET",
            "url": url,
            "detail": detail,
            "impact": impact,
            "remediation": remediation,
            "evidence": evidence,
            "owasp": "A03:2021 / WSTG-INPUT",
        })

    def run(self, urls):
        started = time.time()
        candidates = self.candidate_points(urls)
        print(f"[VALIDATION] Candidate query inputs: {len(candidates)}", flush=True)

        for index, (base_url, parameter) in enumerate(candidates, 1):
            if self.probes >= self.max_probes:
                break
            profile = classify_parameter(parameter)
            values = PROFILES[profile]
            try:
                baseline = self._request(base_url)
            except (requests.RequestException, OutOfScopeError):
                continue

            valid_url = self.mutate(base_url, parameter, values["valid"])
            try:
                valid_response = self._request(valid_url)
            except (requests.RequestException, OutOfScopeError):
                continue

            self.checks.append({
                "url": base_url,
                "parameter": parameter,
                "profile": profile,
                "case": "valid",
                "status": valid_response.status_code,
                "accepted_2xx": 200 <= valid_response.status_code < 300,
                "baseline_status": baseline.status_code,
            })

            for invalid_index, invalid in enumerate(values["invalid"], 1):
                if self.probes >= self.max_probes:
                    break
                probe_url = self.mutate(base_url, parameter, invalid)
                try:
                    response = self._request(probe_url)
                except (requests.RequestException, OutOfScopeError):
                    continue

                accepted = 200 <= response.status_code < 300
                signature = self._error_signature(response)
                check = {
                    "url": base_url,
                    "parameter": parameter,
                    "profile": profile,
                    "case": "invalid",
                    "invalid_index": invalid_index,
                    "status": response.status_code,
                    "accepted_2xx": accepted,
                    "error_signature": signature,
                    "response_bytes": len(response.content),
                }
                if accepted:
                    check["note"] = "Invalid value returned 2xx; manual review required because broad input may be legitimate."
                    check["severity_hint"] = "review"
                self.checks.append(check)

                if response.status_code >= 500:
                    self._finding(
                        f"VALIDATION-5XX-{len(self.findings)+1:03d}",
                        "Invalid input triggered a server error",
                        "Medium", "Medium", probe_url,
                        f"Parameter '{parameter}' classified as {profile} returned HTTP {response.status_code} for an invalid value.",
                        "Unhandled invalid input can expose fragile parsing and availability or information-disclosure risks.",
                        "Validate input at the server boundary and return a controlled 4xx response.",
                        f"profile={profile}; invalid_index={invalid_index}; status={response.status_code}",
                    )
                elif signature:
                    self._finding(
                        f"VALIDATION-ERR-{len(self.findings)+1:03d}",
                        "Invalid input exposed an application error signature",
                        "Medium", "High", probe_url,
                        f"An invalid {profile} value for '{parameter}' exposed an exception/database error signature.",
                        "Detailed errors can reveal implementation and data-layer information.",
                        "Use strict server-side validation and generic production error responses.",
                        f"profile={profile}; invalid_index={invalid_index}; error_signature=True",
                    )

            if index % 5 == 0:
                print(
                    f"[VALIDATION] inputs {index}/{len(candidates)} | "
                    f"probes={self.probes} | findings={len(self.findings)}",
                    flush=True,
                )

        result = {
            "schema": "input-validation-1.0",
            "target": self.target,
            "policy": "same-origin GET-only valid/invalid query validation; no form submission or state changes",
            "profiles": {name: {"valid": data["valid"], "invalid_cases": len(data["invalid"])}
                         for name, data in PROFILES.items()},
            "limits": {
                "max_candidate_points": self.max_urls,
                "max_probes": self.max_probes,
                "rate_rps": self.rate_rps,
                "timeout_seconds": self.timeout,
            },
            "probes": self.probes,
            "checks": self.checks,
            "findings": self.findings,
            "summary": {
                "candidate_points": len(candidates),
                "probes": self.probes,
                "valid_cases": sum(1 for x in self.checks if x["case"] == "valid"),
                "invalid_cases": sum(1 for x in self.checks if x["case"] == "invalid"),
                "accepted_invalid_2xx": sum(1 for x in self.checks if x["case"] == "invalid" and x["accepted_2xx"]),
                "error_signatures": sum(1 for x in self.checks if x["case"] == "invalid" and x.get("error_signature")),
                "findings": len(self.findings),
                "by_severity": dict(Counter(x["severity"] for x in self.findings)),
            },
            "runtime_seconds": round(time.time() - started, 2),
        }
        os.makedirs(config.EVIDENCE_DIR, exist_ok=True)
        path = os.path.join(config.EVIDENCE_DIR, "input_validation.json")
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(result, handle, indent=2, ensure_ascii=False)
        return result


def run_input_validation(target: str, urls, max_urls: int = 30, max_probes: int = 180):
    return InputValidationEngine(target, max_urls=max_urls, max_probes=max_probes).run(urls)
