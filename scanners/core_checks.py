"""Built-in read-only web checks for the Sentinel Core Engine."""
from __future__ import annotations

import hashlib
import re
import uuid
from collections import deque
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit

import requests
from bs4 import BeautifulSoup

from scanners.engine_core import BudgetExceeded, SafeTransport
from utils.scope import OutOfScopeError, assert_same_target, canonical_origin


SECURITY_HEADERS = {
    "content-security-policy": ("Missing Content-Security-Policy", "Low"),
    "x-content-type-options": ("Missing X-Content-Type-Options", "Low"),
    "referrer-policy": ("Missing Referrer-Policy", "Low"),
    "permissions-policy": ("Missing Permissions-Policy", "Info"),
}
SENSITIVE_PATHS = (
    ("/.env", ("database_url=", "secret_key=", "api_key=", "password="), "Potential exposed environment file", "High"),
    ("/.git/HEAD", ("ref: refs/",), "Git metadata appears publicly readable", "Medium"),
    ("/actuator/env", ("propertysources", "activeprofiles"), "Potentially exposed application environment endpoint", "High"),
    ("/server-status", ("server uptime", "requests per second", "scoreboard"), "Server status page appears exposed", "Low"),
    ("/swagger.json", ('"swagger"', '"openapi"'), "API specification is publicly discoverable", "Info"),
    ("/openapi.json", ('"openapi"', '"paths"'), "API specification is publicly discoverable", "Info"),
    ("/backup.zip", (), "Potential backup artifact exposed", "High"),
    ("/database.sql", ("create table", "insert into"), "Potential database dump exposed", "Critical"),
)
_ERROR_SIGNATURES = (
    "sql syntax", "sqlstate", "sqlite error", "mysql error", "postgresql error",
    "unterminated string", "traceback (most recent call last)", "werkzeug debugger",
)
_REFLECTION_MARKER = "SNT_REFLECT_" + uuid.uuid4().hex[:12]


def _safe_url(url: str) -> str:
    p = urlsplit(url)
    return f"{p.scheme}://{p.netloc}{p.path or '/'}"


def _finding(rule_id, title, severity, category, url, detail, impact, remediation,
             evidence_id=None, confidence="Medium", **extra):
    item = {
        "rule_id": rule_id, "title": title, "severity": severity,
        "confidence": confidence, "category": category, "url": _safe_url(url),
        "method": "GET", "detail": detail, "impact": impact,
        "remediation": remediation, "evidence_id": evidence_id,
        "owasp": extra.pop("owasp", "OWASP WSTG-aligned heuristic"),
        "manual_validation_required": bool(extra.pop("manual_validation_required", False)),
    }
    item.update(extra)
    return item


def _last_evidence(client: SafeTransport):
    return client.evidence[-1]["id"] if client.evidence else None


def _get(client: SafeTransport, url: str, headers=None):
    return client.request("GET", url, headers=headers)


def register_core_checks(engine):
    """Register a bounded set of meaningful baseline checks on an engine."""
    engine.register("same_origin_discovery", check_discovery)
    engine.register("security_headers_and_cookies", check_headers_and_cookies)
    engine.register("public_exposure_and_errors", check_public_exposure)
    engine.register("query_input_triage", check_query_inputs)
    engine.register("cors_policy", check_cors_policy)


def check_discovery(client: SafeTransport):
    root = canonical_origin(client.policy.target) + "/"
    queue = deque([root])
    seen = set()
    pages = []
    errors = []
    while queue and len(pages) < client.policy.max_urls:
        url = queue.popleft()
        if url in seen:
            continue
        seen.add(url)
        try:
            response = _get(client, url)
        except BudgetExceeded:
            raise
        except (requests.RequestException, OutOfScopeError) as exc:
            errors.append(f"{_safe_url(url)}: {type(exc).__name__}")
            continue
        pages.append({"url": url, "response": response})
        if "text/html" not in response.headers.get("Content-Type", "").lower():
            continue
        soup = BeautifulSoup(response.text, "html.parser")
        for anchor in soup.select("a[href]"):
            candidate = urljoin(url, anchor.get("href", "").strip())
            p = urlsplit(candidate)
            candidate = urlunsplit((p.scheme, p.netloc, p.path or "/", p.query, ""))
            try:
                assert_same_target(client.policy.target, candidate)
            except OutOfScopeError:
                continue
            if candidate not in seen and candidate not in queue and len(seen) + len(queue) < client.policy.max_urls * 3:
                queue.append(candidate)
    client._sentinel_pages = pages
    status = "partial" if errors else "completed"
    return {
        "status": status, "checks": len(pages), "errors": errors,
        "metadata": {"pages_seen": len(pages), "forms_observed": sum(
            len(BeautifulSoup(row["response"].text, "html.parser").select("form"))
            for row in pages if "text/html" in row["response"].headers.get("Content-Type", "").lower()
        )},
    }


def check_headers_and_cookies(client: SafeTransport):
    pages = getattr(client, "_sentinel_pages", [])
    if not pages:
        return {"status": "skipped", "checks": 0, "errors": ["Discovery returned no pages."]}
    findings = []
    checks = 0
    for row in pages:
        url, response = row["url"], row["response"]
        headers = {str(k).lower(): str(v) for k, v in response.headers.items()}
        checks += 1
        for header, (title, severity) in SECURITY_HEADERS.items():
            if header not in headers:
                findings.append(_finding(
                    "HDR-" + header.upper().replace("-", "_"), title, severity,
                    "Security Configuration", url,
                    f"The response did not include the {header} header.",
                    "The browser has fewer defense-in-depth controls. Impact depends on application behavior and other controls.",
                    f"Configure an appropriate {header} policy for the application and verify it on relevant routes.",
                    _last_evidence(client), confidence="High",
                ))
        if urlsplit(client.policy.target).scheme == "https" and "strict-transport-security" not in headers:
            findings.append(_finding(
                "HDR-HSTS", "Missing Strict-Transport-Security", "Low",
                "Transport Security", url,
                "An HTTPS response did not include Strict-Transport-Security.",
                "Browsers may be more susceptible to protocol downgrade or accidental HTTP navigation.",
                "Enable HSTS after confirming all relevant subdomains and HTTPS routes are configured.",
                _last_evidence(client), confidence="High",
            ))
        server = headers.get("server", "")
        powered = headers.get("x-powered-by", "")
        if server or powered:
            exposed = "; ".join(x for x in (f"Server: {server}" if server else "",
                                             f"X-Powered-By: {powered}" if powered else "") if x)
            findings.append(_finding(
                "HDR-BANNER", "Technology banner disclosed", "Info",
                "Information Disclosure", url, exposed,
                "Technology details can help an attacker prioritize follow-up research; the header alone is not a vulnerability.",
                "Remove or minimize unnecessary technology-identifying response headers where practical.",
                _last_evidence(client), confidence="High",
            ))
        set_cookie = headers.get("set-cookie", "")
        if set_cookie:
            lower = set_cookie.lower()
            cookie_name = set_cookie.split("=", 1)[0].strip().lower()
            session_like = any(token in cookie_name for token in ("session", "auth", "token", "sid"))
            missing = []
            if urlsplit(client.policy.target).scheme == "https" and "secure" not in lower:
                missing.append("Secure")
            if session_like and "httponly" not in lower:
                missing.append("HttpOnly")
            if "samesite=" not in lower:
                missing.append("SameSite")
            if missing:
                findings.append(_finding(
                    "COOKIE-FLAGS", "Cookie missing recommended security attributes",
                    "Medium" if session_like else "Low", "Session Management", url,
                    f"Observed Set-Cookie value is missing: {', '.join(missing)}. Cookie values are not copied into this finding.",
                    "Cookie exposure to script or insecure transport can increase session theft or cross-site request risks.",
                    "Set Secure for HTTPS cookies, HttpOnly for session identifiers, and an appropriate SameSite policy. Review each cookie independently.",
                    _last_evidence(client), confidence="Medium", manual_validation_required=True,
                ))
        if "text/html" in headers.get("content-type", ""):
            soup = BeautifulSoup(response.text, "html.parser")
            for form in soup.select("form"):
                action = urljoin(url, form.get("action") or url)
                method = (form.get("method") or "GET").upper()
                try:
                    assert_same_target(client.policy.target, action)
                except OutOfScopeError:
                    findings.append(_finding(
                        "FORM-EXTERNAL-ACTION", "Form submits to a different origin", "Medium",
                        "Client-Side Security", url,
                        f"A form uses method {method} and an action on a different origin. The form was not submitted.",
                        "Sensitive user input could be sent to an unintended external origin.",
                        "Verify the action is intentional, use HTTPS, and avoid sending credentials or personal data to untrusted origins.",
                        _last_evidence(client), confidence="Medium", manual_validation_required=True,
                    ))
    return {"status": "completed", "checks": checks, "findings": findings}


def check_public_exposure(client: SafeTransport):
    findings = []
    checks = 0
    root = canonical_origin(client.policy.target)
    for path, markers, title, severity in SENSITIVE_PATHS:
        url = root + path
        try:
            response = _get(client, url)
        except BudgetExceeded:
            raise
        except requests.RequestException:
            continue
        checks += 1
        body = response.text[:250000].lower()
        if response.status_code != 200:
            continue
        marker_hit = bool(markers) and any(marker in body for marker in markers)
        if markers and not marker_hit:
            continue
        if not markers:
            # Never flag a generic SPA/404 fallback merely because it returned 200.
            content_type = response.headers.get("Content-Type", "").lower()
            marker_hit = (
                path.endswith(".zip") and ("application/zip" in content_type or response.content.startswith(b"PK\x03\x04"))
                or path.endswith(".sql") and ("create table" in body or "insert into" in body)
            )
            if not marker_hit:
                continue
        findings.append(_finding(
            "EXP-" + hashlib.sha256(path.encode()).hexdigest()[:8].upper(),
            title, severity, "Information Disclosure", url,
            f"GET {path} returned HTTP 200 and matched a path-specific content signature.",
            "Public access to configuration, repository metadata, diagnostics, API descriptions or backups may reveal implementation details or secrets.",
            "Remove the artifact from the public web root, block access at the server, rotate any exposed credentials, and verify with a fresh request.",
            _last_evidence(client), confidence="High" if severity in {"High", "Critical"} else "Medium",
            manual_validation_required=True,
        ))
    return {"status": "completed", "checks": checks, "findings": findings}


def check_query_inputs(client: SafeTransport):
    pages = getattr(client, "_sentinel_pages", [])
    findings = []
    checks = 0
    visited = set()
    for row in pages:
        url = row["url"]
        parsed = urlsplit(url)
        pairs = parse_qsl(parsed.query, keep_blank_values=True)
        if not pairs:
            continue
        key, _ = pairs[0]
        test_pairs = list(pairs)
        test_pairs[0] = (key, _REFLECTION_MARKER)
        mutated = urlunsplit((parsed.scheme, parsed.netloc, parsed.path, urlencode(test_pairs), ""))
        if mutated in visited:
            continue
        visited.add(mutated)
        try:
            response = _get(client, mutated)
        except BudgetExceeded:
            raise
        except requests.RequestException:
            continue
        checks += 1
        if _REFLECTION_MARKER in response.text:
            findings.append(_finding(
                "INPUT-REFLECTION", "User-controlled query value reflected in response",
                "Low", "Input Validation", url,
                "A unique inert marker was reflected in the response. This does not prove executable XSS.",
                "If the value is rendered into an executable HTML/JavaScript context without contextual encoding, cross-site scripting may be possible.",
                "Trace the value to its rendering context and apply context-aware output encoding. Confirm manually in a browser before classifying as XSS.",
                _last_evidence(client), confidence="Low", manual_validation_required=True,
                parameter=key, test_value=_REFLECTION_MARKER,
            ))
        # A single quote is used only as an error-handling canary; no SQL payload
        # that changes data or attempts to bypass authentication is sent.
        quote_pairs = list(pairs)
        quote_pairs[0] = (key, "'")
        quote_url = urlunsplit((parsed.scheme, parsed.netloc, parsed.path, urlencode(quote_pairs), ""))
        try:
            error_response = _get(client, quote_url)
        except BudgetExceeded:
            raise
        except requests.RequestException:
            continue
        checks += 1
        body = error_response.text[:100000].lower()
        hits = [signature for signature in _ERROR_SIGNATURES if signature in body]
        if hits:
            findings.append(_finding(
                "INPUT-ERROR-DISCLOSURE", "Input mutation triggered a backend error signature",
                "Medium", "Input Validation", url,
                f"A single-quote mutation produced signatures: {', '.join(hits)}. This is not proof of SQL injection.",
                "Detailed backend errors can disclose internals and may indicate missing input validation.",
                "Validate inputs server-side, use parameterized database queries, and return generic errors. Reproduce safely in staging to confirm the root cause.",
                _last_evidence(client), confidence="Medium", parameter=key,
                manual_validation_required=True,
            ))
    return {"status": "completed", "checks": checks, "findings": findings}


def check_cors_policy(client: SafeTransport):
    url = canonical_origin(client.policy.target) + "/"
    try:
        response = _get(client, url, headers={"Origin": "https://sentinel-origin.invalid"})
    except BudgetExceeded:
        raise
    except requests.RequestException as exc:
        return {"status": "partial", "checks": 0, "errors": [f"CORS check request failed: {type(exc).__name__}"]}
    allow_origin = response.headers.get("Access-Control-Allow-Origin", "")
    allow_credentials = response.headers.get("Access-Control-Allow-Credentials", "").lower() == "true"
    findings = []
    if allow_origin == "https://sentinel-origin.invalid" and allow_credentials:
        findings.append(_finding(
            "CORS-REFLECT-CREDENTIALS", "CORS reflects an arbitrary origin with credentials",
            "High", "Access Control", url,
            "The response reflected a sentinel Origin and enabled credentials. Verify whether this behavior applies to authenticated sensitive responses.",
            "A permissive credentialed CORS policy can allow an untrusted site to read responses available to a victim's browser session.",
            "Use an explicit trusted-origin allowlist, never reflect arbitrary Origin values, and only enable credentials for necessary trusted origins.",
            _last_evidence(client), confidence="Medium", manual_validation_required=True,
        ))
    return {"status": "completed", "checks": 1, "findings": findings}
