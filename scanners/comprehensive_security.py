"""Comprehensive, non-destructive web security assessment.

The engine is deliberately aggressive in coverage but read-only:
- same-origin requests only
- GET/HEAD/OPTIONS only
- redirects disabled
- bounded path/probe budgets
- no credential attacks, uploads, writes, deletes or DoS
- findings are evidence-based candidates requiring validation

The checks are aligned to OWASP WSTG areas such as configuration,
information gathering, session/cookie posture, client-side exposure and API
surface discovery.
"""

from __future__ import annotations

import json
import os
import re
import time
from collections import Counter
from urllib.parse import urljoin, urlparse

import requests

import config
from utils.scope import assert_same_target, OutOfScopeError


UA = "Sentinel-Comprehensive/2.0 (authorized security assessment)"

COMMON_PATHS = (
    "/robots.txt",
    "/sitemap.xml",
    "/sitemap_index.xml",
    "/security.txt",
    "/.well-known/security.txt",
    "/crossdomain.xml",
    "/clientaccesspolicy.xml",
    "/.git/HEAD",
    "/.env",
    "/.env.local",
    "/.env.production",
    "/phpinfo.php",
    "/server-status",
    "/server-info",
    "/actuator/health",
    "/actuator/env",
    "/debug",
    "/debug/",
    "/swagger.json",
    "/openapi.json",
    "/api/openapi.json",
    "/swagger/v1/swagger.json",
    "/swagger/v2/swagger.json",
    "/swagger/v3/swagger.json",
    "/api-docs",
    "/graphql",
)

SENSITIVE_MARKERS = (
    "traceback",
    "stack trace",
    "debug toolbar",
    "werkzeug debugger",
    "phpinfo()",
    "environment variables",
    "database_url",
    "secret_key",
    "aws_access_key_id",
    "private_key",
)

SECRET_PATTERNS = (
    (re.compile(r"AKIA[0-9A-Z]{16}"), "AWS access-key-like value"),
    (re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"), "private-key material"),
    (re.compile(r"(?i)\b(?:api[_-]?key|secret[_-]?key|access[_-]?token)\s*[:=]\s*['\"][^'\"]{12,}"), "credential-like assignment"),
)

HEADER_RULES = (
    ("Strict-Transport-Security", "Transport Security"),
    ("Content-Security-Policy", "Client Security"),
    ("X-Content-Type-Options", "Client Security"),
    ("Referrer-Policy", "Privacy / Client Security"),
    ("Permissions-Policy", "Client Security"),
    ("X-Frame-Options", "Clickjacking"),
)

class ComprehensiveSecurityEngine:
    def __init__(self, target: str, urls=None, max_urls: int = 80, max_probes: int = 260,
                 rate_rps: float | None = None, timeout: int | None = None):
        self.target = target.rstrip("/")
        parsed = urlparse(self.target)
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.netloc:
            raise ValueError("Target must be an absolute http:// or https:// URL.")
        self.origin = f"{parsed.scheme.lower()}://{parsed.netloc.lower()}"
        self.max_urls = max(1, min(int(max_urls), 120))
        self.max_probes = max(1, min(int(max_probes), 1000))
        self.rate_rps = max(float(rate_rps or getattr(config, "COMPREHENSIVE_RATE_RPS", 3)), 0.5)
        self.timeout = int(timeout or getattr(config, "COMPREHENSIVE_TIMEOUT", 8))
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": UA, "Accept": "*/*"})
        self.probes = 0
        self.last_request = 0.0
        self.findings = []
        self.checks = []
        self._seen = set()
        self.started = time.monotonic()
        self.seed_urls = [self.target + "/"]
        for url in urls or []:
            if self.same_origin(url):
                self.seed_urls.append(url.rstrip("/") or self.target)
        self.seed_urls = list(dict.fromkeys(self.seed_urls))[: self.max_urls]

    def same_origin(self, url: str) -> bool:
        p, o = urlparse(url), urlparse(self.origin)
        return p.scheme.lower() == o.scheme.lower() and p.netloc.lower() == o.netloc.lower()

    def _request(self, method: str, url: str):
        assert_same_target(self.target, url)
        if self.probes >= self.max_probes:
            raise RuntimeError("comprehensive probe budget exhausted")
        delay = (1.0 / self.rate_rps) - (time.monotonic() - self.last_request)
        if delay > 0:
            time.sleep(delay)
        response = self.session.request(
            method,
            url,
            timeout=self.timeout,
            allow_redirects=False,
            verify=True,
        )
        self.last_request = time.monotonic()
        self.probes += 1
        print(
            f"[COMPREHENSIVE] {method} {self.probes:03d}/{self.max_probes} | "
            f"{response.status_code} | {url}",
            flush=True,
        )
        return response

    def _add(self, fid, title, severity, confidence, category, url, evidence, impact, remediation, *,
             method="GET", parameter=None, owasp=None):
        key = (title, url, parameter)
        if key in self._seen:
            return
        self._seen.add(key)
        self.findings.append({
            "id": f"COMP-{fid}-{len(self.findings)+1:03d}",
            "title": title,
            "severity": severity,
            "confidence": confidence,
            "category": category,
            "method": method,
            "url": url,
            "parameter": parameter,
            "detail": evidence,
            "evidence": evidence,
            "impact": impact,
            "remediation": remediation,
            "owasp": owasp or "OWASP WSTG",
        })

    @staticmethod
    def _is_html(response):
        return "text/html" in response.headers.get("Content-Type", "").lower()

    def _check_headers(self, url, response):
        headers = {k.lower(): v for k, v in response.headers.items()}
        if urlparse(url).scheme.lower() == "https" and "strict-transport-security" not in headers:
            self._add(
                "HDR-HSTS", "HSTS is not present", "Medium", "High", "Transport Security",
                url, "HTTPS response does not contain Strict-Transport-Security.",
                "Browsers may continue accepting insecure HTTP access, increasing downgrade and interception exposure.",
                "Enable HSTS with an appropriate max-age; after validating subdomain readiness, consider includeSubDomains and preload where suitable.",
                owasp="A02:2025 Security Misconfiguration",
            )

        for name, category in HEADER_RULES:
            if name.lower() not in headers:
                severity = "Low" if name != "Content-Security-Policy" else "Medium"
                self._add(
                    f"HDR-{name.upper().replace('-', '')}",
                    f"Missing security response header: {name}",
                    severity, "High", category, url,
                    f"Header '{name}' was absent from {response.status_code} response.",
                    "Missing browser security controls can increase exposure to clickjacking, MIME confusion, information leakage or client-side injection impact.",
                    f"Configure {name} consistently at the application/reverse-proxy layer and validate all relevant routes.",
                    owasp="A02:2025 Security Misconfiguration",
                )

        server = response.headers.get("Server", "")
        powered = response.headers.get("X-Powered-By", "")
        if server or powered:
            value = "; ".join(x for x in (f"Server={server}" if server else "", f"X-Powered-By={powered}" if powered else "") if x)
            self._add(
                "HDR-FP", "Technology fingerprint disclosed in response headers",
                "Low", "High", "Information Disclosure", url,
                value,
                "Technology/version details can help attackers select targeted attack paths.",
                "Remove unnecessary framework/runtime identification headers and avoid exposing precise version data.",
                owasp="A05:2025 Security Misconfiguration",
            )

        cookies = response.headers.get("Set-Cookie", "")
        if cookies:
            lowered = cookies.lower()
            if "secure" not in lowered and urlparse(url).scheme.lower() == "https":
                self._add("COOKIE-SEC", "Session cookie missing Secure attribute", "Medium", "Medium",
                          "Session Management", url, "Set-Cookie did not contain Secure.",
                          "A session cookie may be sent over an insecure channel if HTTP access becomes possible.",
                          "Mark sensitive cookies Secure and validate the complete authentication/session cookie set.")
            if "httponly" not in lowered:
                self._add("COOKIE-HTTPONLY", "Cookie missing HttpOnly attribute", "Low", "Medium",
                          "Session Management", url, "Set-Cookie did not contain HttpOnly.",
                          "Client-side script may be able to read a sensitive cookie after an XSS compromise.",
                          "Use HttpOnly for session identifiers unless client-side access is explicitly required.")
            if "samesite" not in lowered:
                self._add("COOKIE-SAMESITE", "Cookie missing SameSite attribute", "Low", "Medium",
                          "Session Management", url, "Set-Cookie did not contain SameSite.",
                          "Cross-site request contexts may have fewer browser-side protections.",
                          "Set an explicit SameSite policy appropriate to the authentication flow and validate cross-site workflows.")

        cache = response.headers.get("Cache-Control", "")
        if ("login" in url.lower() or "account" in url.lower() or "admin" in url.lower()) and not cache:
            self._add("CACHE-SENSITIVE", "Sensitive-looking page has no Cache-Control header", "Low", "Low",
                      "Configuration", url, "URL suggests an account/login/admin surface but Cache-Control is absent.",
                      "Intermediary or browser caching may retain sensitive responses longer than intended.",
                      "Define explicit cache policy for authenticated and sensitive responses; validate through browser and proxy behavior.")

    def _check_body(self, url, response):
        if not response.content:
            return
        body = response.text[:1_500_000]
        lower = body.lower()

        for pattern, label in SECRET_PATTERNS:
            if pattern.search(body):
                self._add(
                    "BODY-SECRET", f"Potential {label} exposed in response", "High", "Medium",
                    "Sensitive Data Exposure", url,
                    f"Pattern matching {label} was detected in the response body.",
                    "Exposed credentials or key material can permit unauthorized access to dependent services.",
                    "Remove secrets from client-visible artifacts, rotate any real exposed credential, and load secrets only on trusted server-side paths.",
                    owasp="A02:2025 Security Misconfiguration",
                )

        matched = [marker for marker in SENSITIVE_MARKERS if marker in lower]
        if matched:
            self._add(
                "BODY-DEBUG", "Verbose diagnostic information exposed",
                "Medium", "Medium", "Error Handling", url,
                f"Detected markers: {', '.join(matched[:8])}",
                "Diagnostic output can disclose stack, framework, environment or database information useful for attack planning.",
                "Disable production debug output and return generic client errors while keeping detailed diagnostics in server-side logs.",
                owasp="A10:2025 Mishandling of Exceptional Conditions",
            )

        if "index of /" in lower and ("<title>index of" in lower or "<h1>index of" in lower):
            self._add(
                "BODY-DIR", "Directory listing appears enabled", "Medium", "High",
                "Configuration", url,
                "Response contains common directory-index markers.",
                "Directory listings can expose backups, source files, logs and other unintended resources.",
                "Disable directory indexing and explicitly control which static resources are public.",
                owasp="A02:2025 Security Misconfiguration",
            )

    def _check_common_path(self, path):
        url = urljoin(self.origin + "/", path.lstrip("/"))
        try:
            response = self._request("GET", url)
        except (requests.RequestException, OutOfScopeError):
            return
        if response.status_code in {200, 206}:
            self._check_headers(url, response)
            self._check_body(url, response)
            if path in {"/.git/HEAD", "/.env", "/.env.local", "/.env.production", "/phpinfo.php",
                        "/server-status", "/server-info", "/actuator/env", "/debug", "/debug/"}:
                self._add(
                    "EXPOSED-PATH", f"Potentially sensitive resource accessible: {path}",
                    "High" if path in {"/.env", "/.env.local", "/.env.production", "/.git/HEAD"} else "Medium",
                    "High", "Configuration", url,
                    f"GET {path} returned HTTP {response.status_code}.",
                    "Publicly accessible operational, source-control, environment or diagnostic resources can disclose secrets or internal architecture.",
                    "Remove or access-control the resource at the server/proxy layer and verify it is not present in the public deployment artifact.",
                    owasp="A02:2025 Security Misconfiguration",
                )

    def _check_options(self, url):
        try:
            response = self._request("OPTIONS", url)
        except (requests.RequestException, OutOfScopeError):
            return
        allow = response.headers.get("Allow", "")
        dangerous = {m for m in re.split(r"\s*,\s*", allow.upper()) if m in {"PUT", "PATCH", "DELETE", "CONNECT", "TRACE"}}
        if dangerous:
            self._add(
                "METHODS", "Potentially unnecessary HTTP methods advertised", "Low", "Medium",
                "Configuration", url,
                f"Allow: {allow}",
                "Unnecessary methods increase attack surface and may expose state-changing or diagnostic behavior.",
                "Disable methods that are not required by the application and enforce authorization server-side.",
                method="OPTIONS",
                owasp="A02:2025 Security Misconfiguration",
            )

    def run(self):
        urls = list(dict.fromkeys(self.seed_urls))[: self.max_urls]
        started = time.monotonic()

        for url in urls:
            if self.probes >= self.max_probes:
                break
            try:
                response = self._request("GET", url)
            except (requests.RequestException, OutOfScopeError):
                continue
            self._check_headers(url, response)
            self._check_body(url, response)
            self._check_options(url)

        for path in COMMON_PATHS:
            if self.probes >= self.max_probes:
                break
            self._check_common_path(path)

        result = {
            "schema": "comprehensive-security-2.0",
            "target": self.target,
            "policy": "same-origin GET/OPTIONS assessment; redirects disabled; no state-changing requests",
            "limits": {
                "max_urls": self.max_urls,
                "max_probes": self.max_probes,
                "rate_rps": self.rate_rps,
                "timeout_seconds": self.timeout,
                "common_paths": len(COMMON_PATHS),
            },
            "probes": self.probes,
            "checks": self.checks,
            "findings": self.findings,
            "summary": {
                "urls_tested": len(urls),
                "probes": self.probes,
                "findings": len(self.findings),
                "by_severity": dict(Counter(x["severity"] for x in self.findings)),
            },
            "runtime_seconds": round(time.monotonic() - started, 2),
        }
        os.makedirs(config.EVIDENCE_DIR, exist_ok=True)
        with open(os.path.join(config.EVIDENCE_DIR, "comprehensive_security.json"), "w", encoding="utf-8") as handle:
            json.dump(result, handle, indent=2, ensure_ascii=False)
        return result


def run_comprehensive_security(target: str, urls=None, max_urls: int = 80, max_probes: int = 260):
    return ComprehensiveSecurityEngine(target, urls=urls, max_urls=max_urls, max_probes=max_probes).run()
