"""Passive API attack-surface discovery for authorized web assessments.

This phase inventories documented APIs without attempting authentication bypass,
state-changing requests, credential attacks, or destructive operations.
"""

from __future__ import annotations

import json
import os
import re
import time
from collections import Counter
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup

import config


UA = "Sentinel-APISurface/1.0 (authorized security assessment)"
DEFAULT_TIMEOUT = getattr(config, "SECURITY_TIMEOUT", 10)
DEFAULT_RPS = max(float(getattr(config, "SECURITY_RATE_RPS", 2)), 0.2)

SPEC_PATHS = (
    "/openapi.json",
    "/swagger.json",
    "/api-docs",
    "/api-docs.json",
    "/v1/openapi.json",
    "/v2/openapi.json",
    "/v3/openapi.json",
    "/swagger/v1/swagger.json",
    "/swagger/v2/swagger.json",
    "/swagger/v3/swagger.json",
)

SPEC_MARKERS = ("openapi", "swagger", "paths")


class ApiSurfaceEngine:
    """Discover and describe an application's documented API surface."""

    def __init__(self, target: str, max_probes: int = 40):
        target = target.rstrip("/")
        parsed = urlparse(target)
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.netloc:
            raise ValueError("Target must be an absolute http:// or https:// URL.")
        self.target = target
        self.origin = f"{parsed.scheme.lower()}://{parsed.netloc.lower()}"
        self.max_probes = max(1, min(int(max_probes), 100))
        self.probes = 0
        self.last_request = 0.0
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": UA, "Accept": "*/*"})
        self.checks = []
        self.findings = []
        self.specs = []
        self.endpoints = []

    def same_origin(self, url: str) -> bool:
        p = urlparse(url)
        o = urlparse(self.origin)
        return p.scheme.lower() == o.scheme.lower() and p.netloc.lower() == o.netloc.lower()

    def request(self, url: str):
        if not self.same_origin(url):
            raise ValueError(f"Out-of-origin URL blocked: {url}")
        if self.probes >= self.max_probes:
            raise RuntimeError("API probe budget exhausted")
        interval = 1.0 / DEFAULT_RPS
        delay = interval - (time.monotonic() - self.last_request)
        if delay > 0:
            time.sleep(delay)
        response = self.session.get(
            url, timeout=DEFAULT_TIMEOUT, allow_redirects=False, verify=True
        )
        self.last_request = time.monotonic()
        self.probes += 1
        return response

    def add(self, fid, title, severity, confidence, category, url, detail, impact, remediation, evidence, **extra):
        item = {
            "id": fid,
            "title": title,
            "severity": severity,
            "confidence": confidence,
            "category": category,
            "method": "GET",
            "url": url,
            "detail": detail,
            "impact": impact,
            "remediation": remediation,
            "evidence": evidence,
        }
        item.update(extra)
        self.findings.append(item)

    @staticmethod
    def _is_spec(payload):
        if not isinstance(payload, dict):
            return False
        return (
            isinstance(payload.get("openapi"), str)
            or isinstance(payload.get("swagger"), str)
        ) and isinstance(payload.get("paths"), dict)

    def candidate_urls(self):
        candidates = [self.target + path for path in SPEC_PATHS]
        try:
            root = self.request(self.target + "/")
            if "html" in root.headers.get("Content-Type", "").lower():
                soup = BeautifulSoup(root.text[:250000], "html.parser")
                for tag in soup.find_all(["a", "link", "script"]):
                    raw = tag.get("href") or tag.get("src")
                    if not raw:
                        continue
                    if re.search(r"(openapi|swagger|api-docs)(?:\.|/|$)", raw, re.I):
                        candidates.append(urljoin(self.target + "/", raw))
        except requests.RequestException:
            pass

        unique = []
        seen = set()
        for url in candidates:
            clean = url.split("#", 1)[0]
            if clean not in seen and self.same_origin(clean):
                seen.add(clean)
                unique.append(clean)
        return unique[: self.max_probes]

    def parse_spec(self, url, response):
        content_type = response.headers.get("Content-Type", "")
        try:
            payload = response.json()
        except ValueError:
            self.checks.append({
                "check": "api-spec",
                "url": url,
                "status": response.status_code,
                "content_type": content_type,
                "parsed": False,
                "reason": "response was not valid JSON",
            })
            return

        if not self._is_spec(payload):
            return

        version = str(payload.get("openapi") or payload.get("swagger") or "unknown")
        info = payload.get("info") or {}
        servers = []

        if isinstance(payload.get("servers"), list):
            for server in payload["servers"]:
                if isinstance(server, dict) and server.get("url"):
                    servers.append(str(server["url"]))
        elif payload.get("host"):
            scheme = (payload.get("schemes") or ["https"])[0]
            base = str(payload.get("basePath") or "")
            servers.append(f"{scheme}://{payload['host']}{base}")

        root_security = payload.get("security")
        paths = payload.get("paths") or {}
        spec = {
            "url": url,
            "format": "OpenAPI" if "openapi" in payload else "Swagger",
            "version": version,
            "title": info.get("title"),
            "description_present": bool(info.get("description")),
            "servers": servers,
            "path_count": len(paths),
        }
        self.specs.append(spec)

        if servers:
            external_servers = [
                s for s in servers
                if not self.same_origin(urljoin(self.target + "/", s))
            ]
            if external_servers:
                self.add(
                    f"API-SERVER-{len(self.findings)+1:03d}",
                    "API specification lists external server origins",
                    "Info", "High", "API Discovery", url,
                    "The public API specification advertises one or more server URLs outside the exact assessment origin.",
                    "External origins reveal integrated services or alternate deployment surfaces that may require separate authorization and inventory.",
                    "Review documented server URLs and ensure every advertised deployment is intentional and separately protected.",
                    f"External server count={len(external_servers)}; values intentionally recorded only as inventory.",
                    owasp="API9:2023",
                    external_server_count=len(external_servers),
                )

        state_changing = []
        deprecated = []
        securityless = []
        endpoint_index = []

        for path, path_item in paths.items():
            if not isinstance(path_item, dict):
                continue
            for method, operation in path_item.items():
                method_upper = str(method).upper()
                if method_upper not in {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE"}:
                    continue
                operation = operation if isinstance(operation, dict) else {}
                entry = {
                    "path": str(path),
                    "method": method_upper,
                    "operation_id": operation.get("operationId"),
                    "summary": operation.get("summary"),
                    "deprecated": bool(operation.get("deprecated")),
                    "security_declared": "security" in operation,
                    "security_required": operation.get("security") if "security" in operation else root_security,
                    "parameters": [],
                }
                for parameter in operation.get("parameters") or []:
                    if isinstance(parameter, dict):
                        entry["parameters"].append({
                            "name": parameter.get("name"),
                            "in": parameter.get("in"),
                            "required": bool(parameter.get("required")),
                        })
                endpoint_index.append(entry)

                if method_upper in {"POST", "PUT", "PATCH", "DELETE"}:
                    state_changing.append(entry)
                if entry["deprecated"]:
                    deprecated.append(entry)
                if entry["security_required"] in (None, []):
                    securityless.append(entry)

        self.endpoints.extend(endpoint_index)

        self.checks.append({
            "check": "api-spec-parsed",
            "url": url,
            "version": version,
            "title": info.get("title"),
            "root_security_declared": root_security is not None,
            "endpoint_count": len(endpoint_index),
            "state_changing_count": len(state_changing),
            "deprecated_count": len(deprecated),
            "securityless_count": len(securityless),
        })

        if state_changing:
            self.add(
                f"API-METHODS-{len(self.findings)+1:03d}",
                "API specification documents state-changing operations",
                "Info", "High", "API Discovery", url,
                "The API contract documents POST/PUT/PATCH/DELETE operations.",
                "State-changing API routes form a larger authorization and business-logic attack surface.",
                "Include every documented operation in authenticated role/authorization testing and keep the API inventory current.",
                f"Documented state-changing operations={len(state_changing)}.",
                owasp="API5:2023",
                state_changing_count=len(state_changing),
            )

        if deprecated:
            self.add(
                f"API-DEPRECATED-{len(self.findings)+1:03d}",
                "Deprecated API operations remain publicly documented",
                "Low", "High", "API Inventory", url,
                "The API specification marks one or more operations as deprecated.",
                "Stale API versions can become forgotten attack surfaces when they remain deployed without equivalent controls.",
                "Confirm deprecated routes are still required, protected, monitored and scheduled for removal.",
                f"Deprecated operations={len(deprecated)}.",
                owasp="API9:2023",
                deprecated_count=len(deprecated),
            )

        if securityless and root_security is not None:
            self.add(
                f"API-SECURITY-{len(self.findings)+1:03d}",
                "Some documented API operations override inherited security with an empty requirement",
                "Medium", "Medium", "API Authorization", url,
                "At least one operation explicitly declares an empty security requirement while the specification defines security at a higher level.",
                "An empty security requirement can intentionally make an endpoint public; if unintended, it can create an authorization gap.",
                "Review each such endpoint against the intended access-control matrix; do not treat the OpenAPI document alone as proof of a vulnerability.",
                f"Potentially public operations={len(securityless)}.",
                owasp="API5:2023",
                potentially_public_count=len(securityless),
            )

    def run(self):
        started = time.time()
        candidates = self.candidate_urls()
        for url in candidates:
            if self.probes >= self.max_probes:
                break
            try:
                response = self.request(url)
            except (requests.RequestException, ValueError, RuntimeError):
                continue
            self.checks.append({
                "check": "api-candidate",
                "url": url,
                "status": response.status_code,
                "content_type": response.headers.get("Content-Type", ""),
                "length": len(response.content),
            })
            if response.status_code == 200:
                self.parse_spec(url, response)

        result = {
            "schema": "api-surface-1.0",
            "target": self.target,
            "scope_lock": self.origin,
            "scope_policy": "exact target origin; redirects disabled",
            "browser_ui": False,
            "limits": {
                "max_probes": self.max_probes,
                "rate_rps": DEFAULT_RPS,
                "timeout_seconds": DEFAULT_TIMEOUT,
            },
            "probes": self.probes,
            "specs": self.specs,
            "endpoints": self.endpoints[:500],
            "checks": self.checks,
            "findings": self.findings,
            "summary": {
                "specs": len(self.specs),
                "endpoints": len(self.endpoints),
                "findings": len(self.findings),
                "by_severity": dict(Counter(x["severity"] for x in self.findings)),
                "by_category": dict(Counter(x["category"] for x in self.findings)),
            },
            "runtime_seconds": round(time.time() - started, 2),
        }
        os.makedirs(config.EVIDENCE_DIR, exist_ok=True)
        path = os.path.join(config.EVIDENCE_DIR, "api_surface.json")
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(result, handle, indent=2, ensure_ascii=False)
        return result


def run_api_surface(target: str, max_probes: int = 40):
    return ApiSurfaceEngine(target, max_probes=max_probes).run()
