"""Controlled active security checks for authorized targets.

These checks are deliberately bounded and non-destructive. They exercise common
web security controls with harmless canaries and response comparisons; they do
not brute-force credentials, upload malware, delete data, or attempt denial of
service.
"""
import os
import re
import uuid
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse

import requests

from config import EVIDENCE_DIR, RATE_LIMIT_RPS
from utils.http_client import get, TargetConnectionError
from utils.scope import assert_in_scope

_TIMEOUT = 12
_MAX_URLS = 12
_REFLECTION_MARKER = "SENTINEL_CANARY_" + uuid.uuid4().hex[:10]


def _finding(fid, title, severity, confidence, category, url, detail, impact, remediation, evidence, **extra):
    item = {
        "id": fid, "title": title, "severity": severity, "confidence": confidence,
        "category": category, "method": extra.pop("method", "GET"), "url": url,
        "detail": detail, "impact": impact, "remediation": remediation,
        "evidence": evidence,
    }
    item.update(extra)
    return item


def _limited_get(url, headers=None):
    assert_in_scope(url)
    return get(url, tag="active-security", headers=headers or {}, timeout=_TIMEOUT)


def _query_canary(url):
    parsed = urlparse(url)
    params = parse_qsl(parsed.query, keep_blank_values=True)
    if not params:
        return None, None
    name, old = params[0]
    params[0] = (name, _REFLECTION_MARKER)
    test = urlunparse(parsed._replace(query=urlencode(params)))
    return test, name


def _record_json(name, payload):
    os.makedirs(EVIDENCE_DIR, exist_ok=True)
    path = os.path.join(EVIDENCE_DIR, name)
    import json
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, ensure_ascii=False)
    return path


def run_active_security(target: str, urls: list[str], forms: list[dict], telemetry=None,
                        max_urls: int = _MAX_URLS) -> dict:
    """Run bounded active checks against discovered, in-scope URLs."""
    assert_in_scope(target)
    findings = []
    checks = []
    selected = list(dict.fromkeys(urls))[:max_urls]

    def emit(**payload):
        if telemetry:
            telemetry(**payload)

    emit(stage="ACTIVE SECURITY TESTING",
         detail=f"Running bounded active checks against {len(selected)} discovered URLs.",
         log={"time": "", "level": "ok", "message": "Active security phase started."})

    # 1. Method exposure / OPTIONS
    for index, url in enumerate(selected, 1):
        try:
            resp = _limited_get(url, headers={"Accept": "*/*"})
            checks.append({"url": url, "check": "baseline", "status": resp.status_code})
            allow = resp.headers.get("Allow", "")
            if allow:
                methods = {m.strip().upper() for m in allow.split(",")}
                risky = sorted(methods.intersection({"TRACE", "PUT", "PATCH", "DELETE"}))
                if risky:
                    findings.append(_finding(
                        f"ACT-METHOD-{index:03d}", "Potentially exposed HTTP methods",
                        "Low", "Medium", "Configuration", url,
                        "The response advertises methods that can have state-changing or diagnostic semantics.",
                        "Unexpected methods increase attack surface and should be disabled when not required.",
                        "Restrict enabled methods to those required by the application and enforce authorization server-side.",
                        f"Allow: {allow}", method="OPTIONS", parameter="Allow",
                        owasp="WSTG-CONF-10"
                    ))
            emit(checks=index, findings=len(findings), stage="ACTIVE HTTP CONTROLS",
                 detail=f"Checked methods and baseline response: {url}",
                 log={"time":"", "level":"ok", "message":f"HTTP control check {index}/{len(selected)}"})
        except TargetConnectionError:
            continue

    # 2. CORS reflection
    for index, url in enumerate(selected, 1):
        try:
            resp = _limited_get(url, headers={"Origin": "https://sentinel-invalid-origin.invalid"})
            acao = resp.headers.get("Access-Control-Allow-Origin", "")
            acac = resp.headers.get("Access-Control-Allow-Credentials", "").lower()
            if acao == "https://sentinel-invalid-origin.invalid" and acac == "true":
                findings.append(_finding(
                    f"ACT-CORS-{index:03d}", "CORS reflects an arbitrary origin with credentials",
                    "High", "High", "CORS", url,
                    "The application reflected a deliberately invalid Origin while allowing credentials.",
                    "A cross-origin attacker-controlled site may be able to read credentialed responses.",
                    "Use an explicit trusted-origin allowlist and never combine arbitrary origin reflection with credentials.",
                    f"Origin: sentinel-invalid-origin.invalid; ACAO: {acao}; ACAC: {acac}",
                    method="GET", owasp="WSTG-CONF-07"
                ))
            elif acao == "*":
                findings.append(_finding(
                    f"ACT-CORS-WILD-{index:03d}", "Wildcard CORS policy observed",
                    "Low", "Medium", "CORS", url,
                    "The response permits all origins with Access-Control-Allow-Origin: *.",
                    "Wildcard CORS can expose public resources more broadly than intended; risk depends on whether credentials or sensitive data are involved.",
                    "Restrict CORS to the minimum trusted origins when resources are not intentionally public.",
                    f"ACAO: {acao}; ACAC: {acac}", method="GET", owasp="WSTG-CONF-07"
                ))
            emit(checks=index, findings=len(findings), stage="CORS TESTING",
                 detail=f"Origin policy checked: {url}",
                 log={"time":"", "level":"ok", "message":f"CORS check {index}/{len(selected)}"})
        except TargetConnectionError:
            continue

    # 3. Reflected input canary on already-discovered query parameters.
    reflection_count = 0
    for url in selected:
        test_url, parameter = _query_canary(url)
        if not test_url:
            continue
        try:
            resp = _limited_get(test_url)
            if _REFLECTION_MARKER in resp.text:
                reflection_count += 1
                findings.append(_finding(
                    f"ACT-REFLECT-{reflection_count:03d}", "User-controlled input reflected in response",
                    "Medium", "Medium", "Input Validation", test_url,
                    "A unique inert canary was reflected into the HTTP response. Reflection alone does not prove XSS.",
                    "Unsafe output encoding at the reflection point can become script injection if executable context is reached.",
                    "Trace the parameter into the rendered DOM and apply context-appropriate output encoding.",
                    f"Marker {_REFLECTION_MARKER} reflected for parameter '{parameter}'.",
                    parameter=parameter, owasp="WSTG-INPV-01"
                ))
        except TargetConnectionError:
            continue

    # 4. Form security posture without submitting state-changing forms.
    csrf_missing = 0
    password_autocomplete = 0
    for form in forms[:40]:
        method = (form.get("method") or "GET").upper()
        action = form.get("action") or form.get("page") or target
        if not action.startswith("http"):
            action = urljoin(target + "/", action)
        if method in {"POST", "PUT", "PATCH", "DELETE"}:
            inputs = {str(x).lower() for x in form.get("inputs", [])}
            token_names = {"csrf", "_csrf", "csrf_token", "xsrf", "_xsrf", "authenticity_token"}
            if not inputs.intersection(token_names):
                csrf_missing += 1
                findings.append(_finding(
                    f"ACT-CSRF-{csrf_missing:03d}", "State-changing form may lack an obvious CSRF token",
                    "Medium", "Medium", "Session Management", action,
                    "A state-changing form was discovered without a conventional CSRF token field.",
                    "If the server relies only on ambient browser credentials, cross-site requests may trigger unintended actions.",
                    "Use a robust server-validated CSRF defense appropriate to the application's authentication model.",
                    f"Form method={method}; inputs={sorted(inputs)}; action={action}",
                    method=method, owasp="WSTG-SESS-05"
                ))

    # 5. Error disclosure using one random, non-existent path.
    error_url = target.rstrip("/") + "/__sentinel_nonexistent_" + uuid.uuid4().hex[:12]
    try:
        resp = _limited_get(error_url)
        body = resp.text[:12000].lower()
        signatures = [
            "traceback (most recent call last)",
            "stack trace", "sqlstate", "exception in thread",
            "undefined variable", "fatal error", "debug mode",
        ]
        hits = [s for s in signatures if s in body]
        if hits:
            findings.append(_finding(
                "ACT-ERROR-001", "Potential verbose error disclosure",
                "Medium", "High", "Error Handling", error_url,
                "A deliberately non-existent path produced a response containing framework/error signatures.",
                "Detailed errors can reveal implementation details useful for targeted attacks.",
                "Return generic production errors and keep stack traces/debug output out of user-facing responses.",
                f"HTTP {resp.status_code}; signatures={hits}", method="GET", owasp="WSTG-ERRH-02"
            ))
    except TargetConnectionError:
        pass

    # 6. HTTPS mixed-content references on discovered HTML pages.
    mixed = 0
    for url in selected:
        if not url.lower().startswith("https://"):
            continue
        try:
            resp = _limited_get(url)
            html = resp.text[:250000]
            refs = re.findall(r'''(?:src|href|action)\s*=\s*["'](http://[^"']+)["']''', html, re.I)
            if refs:
                mixed += len(refs)
                findings.append(_finding(
                    f"ACT-MIXED-{mixed:03d}", "Potential mixed-content resource",
                    "Medium", "High", "Transport Security", url,
                    "An HTTPS page contains direct HTTP resource references.",
                    "Browsers may block or downgrade insecure resources, and unencrypted subresources can expose integrity or confidentiality risks.",
                    "Serve all security-sensitive resources over HTTPS and use relative/HTTPS URLs.",
                    f"HTTP references: {refs[:10]}", method="GET", owasp="WSTG-CONF-07"
                ))
        except TargetConnectionError:
            continue

    result = {
        "target": target,
        "urls_tested": selected,
        "checks": checks,
        "findings": findings,
        "summary": {
            "urls_tested": len(selected),
            "forms_reviewed": min(len(forms), 40),
            "findings": len(findings),
        },
        "reflection_marker": _REFLECTION_MARKER,
    }
    _record_json("active_security.json", result)
    emit(stage="ACTIVE SECURITY COMPLETE", status="RUNNING", checks=len(checks),
         findings=len(findings), progress=90,
         detail=f"Active security checks complete: {len(findings)} observations.",
         log={"time":"", "level":"ok", "message":"Active security phase completed."})
    return result
