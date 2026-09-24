"""Deep, security-only assessment engine.

This module is intentionally separate from the UI/compatibility pipeline.
It performs an aggressive-but-non-destructive GET/HEAD/OPTIONS assessment
against an exact authorized origin. It never follows redirects to another
host, never submits discovered forms, never writes/deletes resources, and
never attempts credential attacks or denial of service.

The goal is high-signal discovery of security weaknesses while keeping the
test deterministic and suitable for an owned production site.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import time
import uuid
from collections import Counter
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse

import requests

import config
from bs4 import BeautifulSoup
from reports.report_generator import generate


UA = "Sentinel-DeepSecurity/1.0 (authorized security assessment)"
TIMEOUT = getattr(config, "SECURITY_TIMEOUT", 10)
MAX_URLS = getattr(config, "SECURITY_MAX_URLS", 40)
MAX_PROBES = getattr(config, "SECURITY_MAX_PROBES", 180)
RATE_RPS = max(float(getattr(config, "SECURITY_RATE_RPS", 2)), 0.2)
SENTINEL = "SENTINEL-" + uuid.uuid4().hex[:12]
EXTERNAL = "https://sentinel-invalid-origin.invalid"
ERROR_SIGNATURES = (
    "traceback (most recent call last)",
    "stack trace",
    "sqlstate",
    "sql syntax",
    "mysql",
    "postgresql",
    "sqlite error",
    "odbc",
    "ora-",
    "unterminated string",
    "fatal error",
    "exception in thread",
    "debug mode",
    "undefined variable",
)
SECRET_PATTERNS = (
    r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
    r"AKIA[0-9A-Z]{16}",
    r"(?i)(api[_-]?key|secret[_-]?key|access[_-]?token)\s*[:=]\s*['\"][^'\"]{12,}",
    r"(?i)(password|passwd|pwd)\s*[:=]\s*['\"][^'\"]{4,}",
)
REDIRECT_KEYS = {"next", "url", "uri", "redirect", "redirect_url", "return", "return_url", "continue", "dest", "destination", "target", "callback"}
SENSITIVE_PATHS = (
    "/.env", "/.git/config", "/.git/HEAD", "/config.json", "/config.php",
    "/phpinfo.php", "/server-status", "/server-info", "/debug", "/actuator",
    "/actuator/env", "/swagger.json", "/openapi.json", "/api-docs",
    "/.well-known/security.txt", "/backup.zip", "/backup.tar.gz", "/db.sql",
    "/database.sql", "/dump.sql", "/web.config", "/composer.json",
    "/package.json", "/package-lock.json",
)


class DeepSecurityEngine:
    def __init__(self, target: str, max_urls: int = MAX_URLS, max_probes: int = MAX_PROBES):
        target = target.rstrip("/")
        parsed = urlparse(target)
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.netloc:
            raise ValueError("Target must be an absolute http:// or https:// URL.")
        self.target = target
        self.origin = f"{parsed.scheme.lower()}://{parsed.netloc.lower()}"
        self.max_urls = max_urls
        self.max_probes = max_probes
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": UA, "Accept": "*/*"})
        self.findings: list[dict] = []
        self.checks: list[dict] = []
        self._last_request = 0.0
        self._probe_count = 0

    def _pace(self):
        interval = 1.0 / RATE_RPS
        delay = interval - (time.monotonic() - self._last_request)
        if delay > 0:
            time.sleep(delay)

    def request(self, method: str, url: str, headers=None, allow_redirects=False):
        if not self._same_origin(url):
            raise ValueError(f"Out-of-origin URL blocked: {url}")
        if self._probe_count >= self.max_probes:
            raise RuntimeError("probe budget exhausted")
        self._pace()
        started = time.monotonic()
        response = self.session.request(
            method, url, headers=headers or {}, timeout=TIMEOUT,
            allow_redirects=allow_redirects, verify=True,
        )
        self._last_request = time.monotonic()
        self._probe_count += 1
        return response, round(time.monotonic() - started, 3)

    def add(self, fid, title, severity, confidence, category, url, detail, impact, remediation, evidence, **extra):
        item = {
            "id": fid,
            "title": title,
            "severity": severity,
            "confidence": confidence,
            "category": category,
            "method": extra.pop("method", "GET"),
            "url": url,
            "detail": detail,
            "impact": impact,
            "remediation": remediation,
            "evidence": evidence,
        }
        item.update(extra)
        self.findings.append(item)

    def record(self, **item):
        self.checks.append(item)

    @staticmethod
    def fingerprint(response):
        body = response.text[:50000]
        return {
            "status": response.status_code,
            "length": len(response.content),
            "content_type": response.headers.get("Content-Type", ""),
            "location": response.headers.get("Location", ""),
            "body_sha256_12": hashlib.sha256(body.encode("utf-8", "ignore")).hexdigest()[:12],
        }

    def _same_origin(self, url: str) -> bool:
        parsed = urlparse(url)
        origin = urlparse(self.origin)
        return parsed.scheme.lower() == origin.scheme.lower() and parsed.netloc.lower() == origin.netloc.lower()

    def crawl(self):
        queue = [self.target + "/"]
        visited = set()
        urls = []
        forms = []

        while queue and len(urls) < self.max_urls and self._probe_count < self.max_probes:
            url = queue.pop(0).split("#", 1)[0]
            if url in visited or not self._same_origin(url):
                continue
            visited.add(url)
            try:
                response, _ = self.request("GET", url)
            except requests.RequestException:
                continue
            urls.append(url)

            if "text/html" not in response.headers.get("Content-Type", "").lower():
                continue

            soup = BeautifulSoup(response.text, "html.parser")
            for form in soup.find_all("form"):
                action = urljoin(url, form.get("action", url)).split("#", 1)[0]
                if self._same_origin(action):
                    forms.append({
                        "page": url,
                        "action": action,
                        "method": form.get("method", "GET").upper(),
                        "inputs": [inp.get("name") for inp in form.find_all(["input", "textarea"]) if inp.get("name")],
                    })

            for anchor in soup.find_all("a", href=True):
                next_url = urljoin(url, anchor["href"]).split("#", 1)[0]
                if self._same_origin(next_url) and next_url not in visited:
                    queue.append(next_url)

        return urls, forms

    def baseline_and_headers(self, urls):
        for index, url in enumerate(urls, 1):
            try:
                resp, elapsed = self.request("GET", url)
            except requests.RequestException as exc:
                self.record(check="baseline", url=url, error=str(exc))
                continue

            fp = self.fingerprint(resp)
            self.record(check="baseline", url=url, elapsed=elapsed, **fp)

            missing = []
            required = ("Content-Security-Policy", "X-Content-Type-Options", "Referrer-Policy", "Permissions-Policy")
            if url.lower().startswith("https://"):
                required = required + ("Strict-Transport-Security",)
            for header in required:
                if not resp.headers.get(header):
                    missing.append(header)
            if missing:
                self.add(
                    f"DS-HEAD-{index:03d}", "Missing security response headers",
                    "Low", "High", "Security Headers", url,
                    "One or more recommended browser/security policy headers were absent.",
                    "Missing controls can weaken defense-in-depth against browser-side attacks and transport downgrade risks.",
                    "Configure security headers appropriate to the application and verify them on security-sensitive routes.",
                    f"Missing: {', '.join(missing)}",
                    method="GET", owasp="WSTG-CONF-14",
                )

            server = resp.headers.get("Server", "")
            powered = resp.headers.get("X-Powered-By", "")
            if server or powered:
                self.add(
                    f"DS-FP-{index:03d}", "Technology fingerprint disclosed in response headers",
                    "Info", "High", "Information Disclosure", url,
                    "The response exposes server/framework identification headers.",
                    "Version and platform disclosure can improve attacker fingerprinting.",
                    "Minimize unnecessary technology/version disclosure at the edge.",
                    f"Server={server!r}; X-Powered-By={powered!r}",
                    method="GET", owasp="WSTG-INFO-02",
                )

            raw_cookie_headers = []
            try:
                raw_cookie_headers = list(resp.raw.headers.getlist("Set-Cookie"))
            except Exception:
                combined = resp.headers.get("Set-Cookie", "")
                if combined:
                    raw_cookie_headers = [combined]
            for cookie in raw_cookie_headers:
                c = cookie.strip()
                if not c:
                    continue
                lower = c.lower()
                cookie_name = c.split("=", 1)[0].strip().lower()
                sensitive_name = any(token in cookie_name for token in ("session", "auth", "token", "jwt", "sid"))
                if "secure" not in lower and url.lower().startswith("https://"):
                    self.add(
                        f"DS-COOKIE-SECURE-{index:03d}-{len(self.findings)}",
                        "HTTPS response sets a cookie without Secure",
                        "Medium" if sensitive_name else "Low", "High", "Session Management", url,
                        "A cookie was observed without the Secure attribute on an HTTPS response.",
                        "The cookie may be exposed if transmitted over an insecure channel.",
                        "Set Secure on cookies that carry authentication or sensitive state; review non-sensitive cookies separately.",
                        c[:300], method="GET", owasp="WSTG-SESS-02",
                        cookie_name=cookie_name,
                    )
                if sensitive_name and "httponly" not in lower:
                    self.add(
                        f"DS-COOKIE-HTTPONLY-{index:03d}-{len(self.findings)}",
                        "Potentially sensitive cookie lacks HttpOnly",
                        "Medium", "High", "Session Management", url,
                        "A cookie whose name suggests session/authentication state was observed without HttpOnly.",
                        "Client-side script access can increase the impact of XSS.",
                        "Set HttpOnly on server-managed authentication/session cookies where compatible.",
                        c[:300], method="GET", owasp="WSTG-SESS-02",
                        cookie_name=cookie_name,
                    )
                if sensitive_name and "samesite=" not in lower:
                    self.add(
                        f"DS-COOKIE-SAMESITE-{index:03d}-{len(self.findings)}",
                        "Potentially sensitive cookie lacks SameSite",
                        "Low", "High", "Session Management", url,
                        "A cookie whose name suggests authentication/session state was observed without an explicit SameSite attribute.",
                        "Cross-site request behavior may be less restricted than intended, increasing CSRF exposure depending on application design.",
                        "Set an explicit SameSite policy appropriate to the authentication flow, commonly Lax or Strict where compatible.",
                        c[:300], method="GET", owasp="WSTG-SESS-06",
                        cookie_name=cookie_name,
                    )

    def method_tests(self, urls):
        for index, url in enumerate(urls):
            try:
                opt, _ = self.request("OPTIONS", url)
                self.record(check="OPTIONS", url=url, status=opt.status_code, allow=opt.headers.get("Allow", ""))
                allow = {x.strip().upper() for x in opt.headers.get("Allow", "").split(",") if x.strip()}
                risky = sorted(allow.intersection({"PUT", "PATCH", "DELETE", "CONNECT"}))
                if risky:
                    self.add(
                        f"DS-METHOD-{index:03d}", "State-changing HTTP methods advertised",
                        "Medium", "Medium", "HTTP Methods", url,
                        "OPTIONS advertises methods that can create, modify or delete server-side resources.",
                        "Unexpected methods expand the attack surface; authorization must still be enforced server-side.",
                        "Disable methods not required by the application and restrict required methods to intended routes.",
                        f"Allow={sorted(allow)}; risky={risky}", method="OPTIONS", owasp="WSTG-CONF-06",
                    )
                trace, _ = self.request("TRACE", url, headers={"X-Sentinel-Trace": SENTINEL})
                echoed = SENTINEL.lower() in trace.text.lower()
                self.record(check="TRACE", url=url, status=trace.status_code, echoed=echoed)
                if trace.status_code == 200 and echoed:
                    self.add(
                        f"DS-TRACE-{index:03d}", "TRACE reflects request headers",
                        "Medium", "High", "HTTP Methods", url,
                        "A TRACE request returned the unique test header, indicating request reflection.",
                        "TRACE reflection can expose request metadata and is unnecessary for most production applications.",
                        "Disable TRACE unless there is a documented requirement.",
                        f"HTTP={trace.status_code}; marker_reflected={echoed}",
                        method="TRACE", owasp="WSTG-CONF-06",
                    )
            except requests.RequestException:
                continue

    def cors_tests(self, urls):
        for index, url in enumerate(urls[: min(len(urls), 12)], 1):
            origin = "https://sentinel-invalid-origin.invalid"
            try:
                response, _ = self.request("GET", url, headers={"Origin": origin})
            except requests.RequestException:
                continue

            allow_origin = response.headers.get("Access-Control-Allow-Origin", "")
            allow_credentials = response.headers.get("Access-Control-Allow-Credentials", "")
            self.record(
                check="cors",
                url=url,
                status=response.status_code,
                request_origin=origin,
                allow_origin=allow_origin,
                allow_credentials=allow_credentials,
            )

            reflected = allow_origin.strip() == origin
            wildcard_credentials = allow_origin.strip() == "*" and allow_credentials.lower().strip() == "true"
            if reflected and allow_credentials.lower().strip() == "true":
                self.add(
                    f"DS-CORS-{index:03d}",
                    "CORS reflects arbitrary Origin with credentials enabled",
                    "High", "High", "CORS", url,
                    "The response reflected a controlled cross-origin value and also enabled credentials.",
                    "A permissive credentialed CORS policy can allow an untrusted origin to read authenticated cross-origin responses.",
                    "Allowlist trusted origins and enable credentials only where required.",
                    f"Origin={origin}; Access-Control-Allow-Origin={allow_origin}; Access-Control-Allow-Credentials={allow_credentials}",
                    method="GET", owasp="WSTG-CONF-07",
                )
            elif wildcard_credentials:
                self.add(
                    f"DS-CORS-WILD-{index:03d}",
                    "CORS uses wildcard origin with credentials enabled",
                    "High", "High", "CORS", url,
                    "The response advertised wildcard CORS together with credential support.",
                    "This combination indicates a dangerous cross-origin policy, although browser enforcement details still depend on the endpoint and response.",
                    "Replace wildcard origins with an explicit trusted-origin allowlist and review credential requirements.",
                    f"Access-Control-Allow-Origin={allow_origin}; Access-Control-Allow-Credentials={allow_credentials}",
                    method="GET", owasp="WSTG-CONF-07",
                )

    def query_tests(self, urls):
        vectors = [
            ("reflection", SENTINEL),
            ("sql_quote", "'"),
            ("sql_double_quote", '"'),
            ("boundary", "SENTINEL_BOUNDARY_9f2a"),
            ("template", "{{SENTINEL}}"),
        ]
        for url in urls:
            params = parse_qsl(urlparse(url).query, keep_blank_values=True)
            for idx in range(min(len(params), 4)):
                for label, value in vectors:
                    if self._probe_count >= self.max_probes:
                        return
                    parsed = urlparse(url)
                    mutated = list(params)
                    name = mutated[idx][0]
                    mutated[idx] = (name, value)
                    probe = urlunparse(parsed._replace(query=urlencode(mutated)))
                    try:
                        baseline, _ = self.request("GET", url)
                        response, elapsed = self.request("GET", probe)
                    except requests.RequestException:
                        continue
                    body = response.text[:60000]
                    lower = body.lower()
                    hits = [s for s in ERROR_SIGNATURES if s in lower]
                    reflected = SENTINEL.lower() in lower
                    self.record(check="query-mutation", url=probe, parameter=name, vector=label,
                                status=response.status_code, elapsed=elapsed,
                                baseline_status=baseline.status_code, response_length=len(response.content),
                                error_signatures=hits[:8], marker_reflected=reflected)
                    if hits:
                        self.add(
                            f"DS-INJ-{len(self.findings):04d}",
                            "Server error signal triggered by URL parameter mutation",
                            "Medium", "Medium", "Input Validation", probe,
                            "A harmless syntax-oriented GET mutation produced a backend/framework error signature.",
                            "Error behavior can disclose implementation details and may indicate unsafe input handling.",
                            "Validate and constrain input, use parameterized queries, and return generic production errors.",
                            f"parameter={name}; vector={label}; HTTP={response.status_code}; signatures={hits[:8]}",
                            method="GET", parameter=name, evidence_url=probe, owasp="WSTG-INJT-05",
                        )
                    if label == "reflection" and reflected:
                        self.add(
                            f"DS-XSS-{len(self.findings):04d}",
                            "Reflected input candidate detected",
                            "Medium", "Medium", "Input Validation", probe,
                            "A unique inert marker was reflected into the HTTP response.",
                            "If the reflection reaches an executable browser context without correct encoding, XSS may be possible.",
                            "Validate the exact rendering context and apply context-appropriate output encoding.",
                            f"parameter={name}; marker={SENTINEL}; HTTP={response.status_code}",
                            method="GET", parameter=name, evidence_url=probe, owasp="WSTG-INJT-01",
                        )

    def redirect_and_crlf(self, urls):
        for url in urls:
            params = parse_qsl(urlparse(url).query, keep_blank_values=True)
            for idx, (name, old) in enumerate(params[:4]):
                lower_name = name.lower()
                if lower_name in REDIRECT_KEYS:
                    parsed = urlparse(url)
                    mutated = list(params)
                    mutated[idx] = (name, EXTERNAL)
                    probe = urlunparse(parsed._replace(query=urlencode(mutated)))
                    try:
                        resp, _ = self.request("GET", probe)
                    except requests.RequestException:
                        continue
                    location = resp.headers.get("Location", "")
                    self.record(check="open-redirect", url=probe, parameter=name,
                                status=resp.status_code, location=location)
                    if location.startswith(EXTERNAL):
                        self.add(
                            f"DS-REDIR-{len(self.findings):04d}",
                            "Potential open redirect",
                            "Medium", "High", "Input Validation", probe,
                            "A URL-like parameter caused a redirect response to a controlled invalid external origin.",
                            "Open redirects can support phishing and redirect-chain abuse.",
                            "Allowlist permitted destinations or use opaque server-side destination identifiers.",
                            f"parameter={name}; Location={location[:500]}",
                            method="GET", parameter=name, owasp="WSTG-CLNT-04",
                        )

                parsed = urlparse(url)
                mutated = list(params)
                mutated[idx] = (name, SENTINEL + "%0d%0aX-Sentinel: injected")
                probe = urlunparse(parsed._replace(query=urlencode(mutated)))
                try:
                    resp, _ = self.request("GET", probe)
                except requests.RequestException:
                    continue
                header_hits = {k.lower(): v for k, v in resp.headers.items() if "sentinel" in v.lower() or "injected" in v.lower()}
                self.record(check="crlf", url=probe, parameter=name, status=resp.status_code, header_hits=header_hits)
                if header_hits:
                    self.add(
                        f"DS-CRLF-{len(self.findings):04d}",
                        "Potential response-header injection signal",
                        "High", "Medium", "Input Validation", probe,
                        "A controlled CR/LF canary produced a response header containing the test marker.",
                        "HTTP response splitting can affect redirects, caches and downstream clients.",
                        "Reject CR/LF characters in header-derived input and encode/validate redirect values.",
                        f"parameter={name}; headers={header_hits}",
                        method="GET", parameter=name, owasp="WSTG-INJT-15",
                    )

    def header_routing_tests(self, urls):
        tests = (
            ("Host", "sentinel-invalid-origin.invalid"),
            ("X-Forwarded-Host", "sentinel-invalid-origin.invalid"),
            ("X-Original-URL", "/__sentinel_nonexistent__"),
            ("X-Rewrite-URL", "/__sentinel_nonexistent__"),
        )
        for url in urls[: min(len(urls), 12)]:
            try:
                baseline, _ = self.request("GET", url)
            except requests.RequestException:
                continue
            base_fp = self.fingerprint(baseline)
            for header, value in tests:
                try:
                    response, _ = self.request("GET", url, headers={header: value})
                except requests.RequestException:
                    continue
                body = response.text[:20000].lower()
                changed = (
                    response.status_code != baseline.status_code
                    or abs(len(response.content) - len(baseline.content)) > max(200, len(baseline.content) * 0.25)
                    or value.lower() in response.text.lower()
                )
                self.record(check="header-routing", url=url, header=header,
                            value=value, baseline=base_fp, result=self.fingerprint(response), changed=changed)
                if header in {"X-Original-URL", "X-Rewrite-URL"} and response.status_code == 404 and baseline.status_code != 404:
                    self.add(
                        f"DS-REWRITE-{len(self.findings):04d}",
                        f"Application honors {header}",
                        "Medium", "Medium", "Authorization", url,
                        f"The response changed to a not-found result when {header} pointed to a non-existent path.",
                        "Special URL override headers can create mismatches between edge access controls and application routing.",
                        "Reject untrusted URL-override headers at the edge or ensure normalization and authorization occur consistently.",
                        f"header={header}; value={value}; baseline={baseline.status_code}; mutated={response.status_code}",
                        method="GET", owasp="WSTG-ATHZ-02",
                    )
                if header in {"Host", "X-Forwarded-Host"} and value.lower() in response.text.lower():
                    self.add(
                        f"DS-HOST-{len(self.findings):04d}",
                        f"Potential host-header reflection via {header}",
                        "Medium", "Medium", "Input Validation", url,
                        "A controlled invalid host value was reflected in the response body.",
                        "Host-derived values can affect links, redirects, caches and password-reset URLs.",
                        "Use a strict canonical host allowlist and do not trust forwarded host headers from untrusted clients.",
                        f"header={header}; value={value}",
                        method="GET", owasp="WSTG-INJT-17",
                    )

    def content_disclosure(self, urls):
        # Review discovered HTML/JS for high-signal leakage without printing secret values.
        js_urls = set()
        for url in urls:
            try:
                resp, _ = self.request("GET", url)
            except requests.RequestException:
                continue
            text = resp.text[:250000]
            comments = len(re.findall(r"<!--.*?-->", text, re.S))
            secret_hits = sum(1 for p in SECRET_PATTERNS if re.search(p, text))
            self.record(check="content-review", url=url, comments=comments, secret_pattern_hits=secret_hits)
            if secret_hits:
                self.add(
                    f"DS-LEAK-{len(self.findings):04d}",
                    "Potential secret-like material exposed in page source",
                    "High", "Medium", "Information Disclosure", url,
                    "Page source matched one or more secret/key/password pattern heuristics. Values are intentionally not stored in the report.",
                    "Exposed credentials or keys can permit unauthorized access to connected systems.",
                    "Remove secrets from client-delivered assets and rotate any real credential found.",
                    f"pattern_matches={secret_hits}; response_length={len(resp.content)}",
                    method="GET", owasp="WSTG-INFO-05",
                )
            for src in re.findall(r"""<script[^>]+src=[\"']([^\"']+)[\"']""", text, re.I):
                js = urljoin(url, src)
                try:
                    if self._same_origin(js):
                        js_urls.add(js)
                except Exception:
                    pass

        for js in list(js_urls)[:30]:
            for extra in ("", ".map"):
                candidate = js + extra
                try:
                    resp, _ = self.request("GET", candidate)
                except requests.RequestException:
                    continue
                if resp.status_code < 400:
                    body = resp.text[:300000]
                    hits = sum(1 for p in SECRET_PATTERNS if re.search(p, body))
                    self.record(check="javascript-artifact", url=candidate, status=resp.status_code, secret_pattern_hits=hits)
                    if candidate.endswith(".map") and resp.status_code == 200:
                        self.add(
                            f"DS-SMAP-{len(self.findings):04d}",
                            "JavaScript source map publicly accessible",
                            "Low", "High", "Information Disclosure", candidate,
                            "A source map was directly accessible from a discovered JavaScript asset.",
                            "Source maps can expose source paths and implementation details useful for security analysis.",
                            "Do not publish production source maps unless they are intentionally public and reviewed.",
                            f"HTTP={resp.status_code}; content_length={len(resp.content)}",
                            method="GET", owasp="WSTG-INFO-05",
                        )
                    if hits:
                        self.add(
                            f"DS-JSLEAK-{len(self.findings):04d}",
                            "Potential secret-like material exposed in JavaScript",
                            "High", "Medium", "Information Disclosure", candidate,
                            "A JavaScript asset matched secret/key/password heuristics. Values are not stored.",
                            "Client-visible secrets can be copied and abused outside the application.",
                            "Remove secrets from client assets and rotate exposed credentials.",
                            f"pattern_matches={hits}; content_length={len(resp.content)}",
                            method="GET", owasp="WSTG-INFO-05",
                        )

    def metadata_and_exposure(self):
        candidates = [
            self.target + "/robots.txt",
            self.target + "/sitemap.xml",
            self.target + "/.well-known/security.txt",
        ] + [self.target + path for path in SENSITIVE_PATHS]
        for candidate in list(dict.fromkeys(candidates))[:40]:
            try:
                resp, _ = self.request("GET", candidate)
            except requests.RequestException:
                continue
            body = resp.text[:80000]
            self.record(check="exposure", url=candidate, status=resp.status_code,
                        content_type=resp.headers.get("Content-Type", ""), length=len(resp.content))
            if candidate.endswith(("/.env", "/.git/config", "/config.php", "/web.config", "/db.sql", "/database.sql", "/dump.sql")):
                if resp.status_code == 200 and len(body) > 0:
                    self.add(
                        f"DS-EXPOSE-{len(self.findings):04d}",
                        "Potential sensitive configuration/backup file exposure",
                        "High", "Medium", "Sensitive File Exposure", candidate,
                        "A high-risk configuration or database-style path returned HTTP 200 with content.",
                        "Public configuration or database artifacts can expose secrets and internal application data.",
                        "Remove the artifact from the web root, deny access at the edge, and rotate any exposed secrets.",
                        f"HTTP={resp.status_code}; content_type={resp.headers.get('Content-Type','')}; length={len(resp.content)}",
                        method="GET", owasp="WSTG-CONF-03",
                    )
            if any(x in candidate for x in ("/swagger.json", "/openapi.json", "/api-docs")) and resp.status_code == 200:
                self.add(
                    f"DS-API-DOC-{len(self.findings):04d}",
                    "Public API specification discovered",
                    "Info", "High", "API Discovery", candidate,
                    "An API documentation endpoint returned successfully.",
                    "Public API specifications expand the documented attack surface; exposure is not automatically a vulnerability.",
                    "Review whether API documentation is intended to be public and ensure documented endpoints enforce authorization.",
                    f"HTTP={resp.status_code}; content_type={resp.headers.get('Content-Type','')}",
                    method="GET", owasp="WSTG-INFO-03",
                )

    def error_disclosure(self):
        url = self.target + "/__sentinel_nonexistent_" + uuid.uuid4().hex[:12]
        try:
            resp, _ = self.request("GET", url)
        except requests.RequestException:
            return
        body = resp.text[:50000].lower()
        hits = [x for x in ERROR_SIGNATURES if x in body]
        self.record(check="error-disclosure", url=url, status=resp.status_code, signatures=hits)
        if hits:
            self.add(
                "DS-ERR-001", "Verbose error disclosure on invalid route",
                "Medium", "High", "Error Handling", url,
                "A deliberately invalid route returned recognizable framework/database error text.",
                "Verbose errors disclose implementation details useful for targeted attacks.",
                "Disable debug output and return generic production errors.",
                f"HTTP={resp.status_code}; signatures={hits[:10]}",
                method="GET", owasp="WSTG-ERRH-02",
            )

    def run(self):
        started = time.time()
        budget_exhausted = False
        exhausted_stage = None

        # Probe exhaustion is a normal bounded-scan condition, not a fatal
        # assessment error. Finish the report with the checks completed so far.
        stages = (
            ("crawl", lambda: self.crawl()),
            ("baseline_and_headers", lambda: self.baseline_and_headers(urls)),
            ("method_tests", lambda: self.method_tests(urls)),
            ("cors_tests", lambda: self.cors_tests(urls)),
            ("query_tests", lambda: self.query_tests(urls)),
            ("redirect_and_crlf", lambda: self.redirect_and_crlf(urls)),
            ("header_routing_tests", lambda: self.header_routing_tests(urls)),
            ("content_disclosure", lambda: self.content_disclosure(urls)),
            ("metadata_and_exposure", self.metadata_and_exposure),
            ("error_disclosure", self.error_disclosure),
        )

        urls, forms = [], []
        for stage_name, stage in stages:
            if stage_name != "crawl" and self._probe_count >= self.max_probes:
                budget_exhausted = True
                exhausted_stage = stage_name
                break
            try:
                value = stage()
                if stage_name == "crawl":
                    urls, forms = value
            except RuntimeError as exc:
                if str(exc) == "probe budget exhausted":
                    budget_exhausted = True
                    exhausted_stage = stage_name
                    break
                raise

        result = {
            "schema": "deep-security-1.0",
            "target": self.target,
            "mode": "security-only aggressive non-destructive",
            "browser_ui": False,
            "scope_lock": self.origin,
            "scope_policy": "exact target origin; redirects disabled",
            "limits": {
                "max_urls": self.max_urls,
                "max_probes": self.max_probes,
                "rate_rps": RATE_RPS,
                "timeout_seconds": TIMEOUT,
            },
            "urls_tested": urls,
            "forms_discovered": len(forms),
            "probe_count": self._probe_count,
            "budget_exhausted": budget_exhausted,
            "exhausted_stage": exhausted_stage,
            "checks": self.checks,
            "findings": self.findings,
            "summary": {
                "findings": len(self.findings),
                "by_severity": dict(Counter(x["severity"] for x in self.findings)),
                "by_category": dict(Counter(x["category"] for x in self.findings)),
            },
            "runtime_seconds": round(time.time() - started, 2),
        }
        os.makedirs(config.EVIDENCE_DIR, exist_ok=True)
        with open(os.path.join(config.EVIDENCE_DIR, "deep_security.json"), "w", encoding="utf-8") as handle:
            json.dump(result, handle, indent=2, ensure_ascii=False)

        report = generate(
            self.target,
            self.findings,
            config.EVIDENCE_DIR,
            metadata={
                "profile": "security",
                "methodology": "OWASP WSTG-aligned deep security-only assessment",
                "deep_security": result,
                "headed": False,
                "browser_ui": False,
            },
        )
        result["report"] = {
            "html_path": report["html_path"],
            "json_path": report["json_path"],
            "total_findings": report["report"]["total_findings"],
        }
        # Keep persisted scanner counts authoritative even if report presentation
        # deduplicates repeated observations into fewer report rows.
        result["summary"]["report_findings"] = report["report"]["total_findings"]
        with open(os.path.join(config.EVIDENCE_DIR, "deep_security.json"), "w", encoding="utf-8") as handle:
            json.dump(result, handle, indent=2, ensure_ascii=False)
        return result


def run_deep_security(target: str, max_urls: int = MAX_URLS, max_probes: int = MAX_PROBES):
    return DeepSecurityEngine(target, max_urls=max_urls, max_probes=max_probes).run()
