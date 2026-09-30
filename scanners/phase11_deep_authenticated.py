"""Phase 11: bounded deep authenticated/API differential assessment.

Read-only authenticated assessment with explicit endpoints, two test sessions,
BOLA/IDOR differential checks, workflow authorization checks, method
differentials, bounded parameter fuzzing and JSON evidence.
"""
from __future__ import annotations

import hashlib
import json
import os
import time
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, quote, urlencode, urljoin, urlsplit, urlunsplit

import requests

from utils.scope import assert_same_target

MAX_BODY_BYTES = 200_000
ALLOWED_LOGIN_STATUSES = {200, 201, 202, 204, 302, 303}
DEFAULT_TIMEOUT = 10

# Benign malformed/boundary values only.
FUZZ_VALUES = {
    "text": ["", " ", "A", "A" * 32, "A" * 256, "%20", "%2F", "é", "🙂"],
    "numeric": ["", "0", "-1", "1.5", "abc", "999999999999999999"],
    "identifier": ["", "0", "-1", "abc", "../1", "1%2F2", "%00"],
    "email": ["", "a", "a@", "@example.test", "a@@example.test", "qa@example.test "],
    "boolean": ["", "true", "false", "maybe", "2", "truthy"],
    "date": ["", "2026-09-30", "2026-02-30", "30-09-2026", "not-a-date"],
}

NAME_HINTS = {
    "numeric": ("page", "limit", "offset", "count", "size", "age", "year", "total"),
    "identifier": ("id", "uuid", "key", "token", "order", "user", "account", "product"),
    "email": ("email", "mail"),
    "boolean": ("is_", "has_", "enabled", "active", "admin", "verified"),
    "date": ("date", "day", "month", "year"),
}


def classify_parameter(name: str) -> str:
    lowered = name.lower()
    for profile, hints in NAME_HINTS.items():
        if any(hint in lowered for hint in hints):
            return profile
    return "text"


def fingerprint(response: requests.Response) -> dict[str, Any]:
    body = response.content[:MAX_BODY_BYTES]
    return {
        "status": response.status_code,
        "bytes": len(response.content),
        "content_type": response.headers.get("Content-Type", ""),
        "location": response.headers.get("Location", ""),
        "allow": response.headers.get("Allow", ""),
        "sha256": hashlib.sha256(body).hexdigest(),
    }


def decision(response: requests.Response) -> bool | None:
    if "json" not in response.headers.get("Content-Type", "").lower():
        return None
    try:
        payload = response.json()
    except (ValueError, TypeError):
        return None
    if not isinstance(payload, dict):
        return None
    for key in ("allowed", "authorized", "permitted"):
        if isinstance(payload.get(key), bool):
            return payload[key]
    nested = payload.get("decision")
    if isinstance(nested, dict):
        for key in ("allowed", "authorized", "permitted"):
            if isinstance(nested.get(key), bool):
                return nested[key]
    return None


def build_url(base_url: str, endpoint_template: str, object_id: str | None = None,
              owner: str | None = None, action: str | None = None) -> str:
    if not endpoint_template.startswith("/"):
        raise ValueError("endpoint must be an absolute path beginning with '/'")
    for token, value in (("{id}", object_id), ("{owner}", owner), ("{action}", action)):
        if token in endpoint_template and value is None:
            raise ValueError(f"endpoint contains {token} but no value was supplied")
    rendered = endpoint_template.format(
        id=quote(str(object_id), safe="") if object_id is not None else "",
        owner=quote(str(owner), safe="") if owner is not None else "",
        action=quote(str(action), safe="") if action is not None else "",
    )
    url = urljoin(base_url.rstrip("/") + "/", rendered.lstrip("/"))
    assert_same_target(base_url, url)
    return url


def login_with_env(base_url: str, user_env: str, pass_env: str,
                   login_path: str = "/login") -> requests.Session:
    username, password = os.getenv(user_env), os.getenv(pass_env)
    if not username or not password:
        raise RuntimeError(f"Missing credentials in {user_env}/{pass_env}")
    if not login_path.startswith("/"):
        raise ValueError("login_path must begin with '/'")
    login_url = build_url(base_url, login_path)
    session = requests.Session()
    session.headers.update({"User-Agent": "Sentinel-Phase11-Authorized/1.0"})
    response = session.post(login_url, data={"username": username, "password": password},
                            timeout=DEFAULT_TIMEOUT, allow_redirects=False)
    if response.status_code not in ALLOWED_LOGIN_STATUSES:
        raise RuntimeError(f"Authentication failed for {user_env}: HTTP {response.status_code}")
    return session


def _mutate_query(url: str, name: str, value: str) -> str:
    parts = urlsplit(url)
    pairs = [(k, value if k == name else v)
             for k, v in parse_qsl(parts.query, keep_blank_values=True)]
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(pairs), parts.fragment))


def _query_names(url: str) -> list[str]:
    return list(dict.fromkeys(k for k, _ in parse_qsl(urlsplit(url).query, keep_blank_values=True)))


def _bounded_parameter_fuzz(session: requests.Session, base_url: str,
                            endpoint: str, max_probes: int) -> dict[str, Any]:
    url = build_url(base_url, endpoint)
    names = _query_names(url)
    probes: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    baseline = session.get(url, timeout=DEFAULT_TIMEOUT, allow_redirects=False)
    probes.append({"kind": "baseline", "url": url, "fingerprint": fingerprint(baseline)})

    for name in names:
        profile = classify_parameter(name)
        for value in FUZZ_VALUES[profile]:
            if len(probes) >= max_probes:
                break
            mutated = _mutate_query(url, name, value)
            assert_same_target(base_url, mutated)
            started = time.monotonic()
            response = session.get(mutated, timeout=DEFAULT_TIMEOUT, allow_redirects=False)
            item = {
                "kind": "parameter_fuzz",
                "parameter": name,
                "profile": profile,
                "value_length": len(value),
                "value_preview": value[:80],
                "url": mutated,
                "elapsed_ms": round((time.monotonic() - started) * 1000, 1),
                "fingerprint": fingerprint(response),
            }
            probes.append(item)
            if response.status_code >= 500:
                findings.append({
                    "id": "P11-INPUT-001",
                    "title": "Server error triggered by malformed or boundary input",
                    "severity": "Medium",
                    "confidence": "Medium",
                    "category": "Input Validation",
                    "cwe": "CWE-20",
                    "url": mutated,
                    "method": "GET",
                    "detail": f"Parameter '{name}' with a bounded {profile} test value returned HTTP {response.status_code}.",
                    "impact": "Malformed input may reach an unhandled server-side error path.",
                    "remediation": "Validate type, range, encoding and requiredness at the application boundary and return controlled 4xx responses.",
                    "evidence": item,
                })
        if len(probes) >= max_probes:
            break
    return {"endpoint": endpoint, "parameters": names, "probes": probes, "findings": findings}


def _method_differential(session: requests.Session, base_url: str, endpoint: str) -> dict[str, Any]:
    url = build_url(base_url, endpoint)
    responses = {}
    for method in ("GET", "HEAD", "OPTIONS"):
        response = session.request(method, url, timeout=DEFAULT_TIMEOUT, allow_redirects=False)
        responses[method] = fingerprint(response)
    findings = []
    allow = responses["OPTIONS"].get("allow", "")
    if allow:
        findings.append({
            "id": "P11-METHOD-OBS-001",
            "title": "HTTP method capability exposed by OPTIONS",
            "severity": "Info",
            "confidence": "High",
            "category": "API / Method Differential",
            "url": url,
            "method": "OPTIONS",
            "detail": f"Server advertised Allow: {allow}. Review whether every advertised method has the intended authorization policy.",
            "impact": "Method exposure should be reviewed when endpoint authorization differs by HTTP verb.",
            "remediation": "Apply authorization consistently to every supported method and explicitly reject unsupported verbs.",
            "evidence": responses,
        })
    return {"url": url, "responses": responses, "findings": findings}


def _bola(session_a: requests.Session, session_b: requests.Session, base_url: str,
          endpoint: str, object_a: str, object_b: str) -> dict[str, Any]:
    if object_a == object_b:
        raise ValueError("BOLA object IDs must differ")
    urls = {
        "a_own": build_url(base_url, endpoint, object_id=object_a),
        "a_other": build_url(base_url, endpoint, object_id=object_b),
        "b_own": build_url(base_url, endpoint, object_id=object_b),
        "b_other": build_url(base_url, endpoint, object_id=object_a),
    }
    sessions = {"a_own": session_a, "a_other": session_a, "b_own": session_b, "b_other": session_b}
    responses = {}
    for key, url in urls.items():
        response = sessions[key].get(url, timeout=DEFAULT_TIMEOUT, allow_redirects=False)
        responses[key] = {"url": url, "fingerprint": fingerprint(response), "decision": decision(response)}
    bypasses = []
    for owner_key, other_key in (("a_own", "a_other"), ("b_own", "b_other")):
        own, other = responses[owner_key], responses[other_key]
        if other["decision"] is True:
            bypasses.append(other_key)
        elif (other["decision"] is None and own["fingerprint"]["status"] == 200
              and other["fingerprint"]["status"] == 200
              and own["fingerprint"]["sha256"] == other["fingerprint"]["sha256"]):
            bypasses.append(other_key)
    findings = []
    if bypasses:
        findings.append({
            "id": "P11-BOLA-001",
            "title": "Potential authenticated BOLA/IDOR object authorization bypass",
            "severity": "High",
            "confidence": "High",
            "category": "Authorization / BOLA",
            "cwe": "CWE-639",
            "owasp": "API1:2023 Broken Object Level Authorization",
            "method": "GET",
            "url": responses[bypasses[0]]["url"],
            "detail": "A session accessed a different disposable object's endpoint with an allowed or indistinguishable successful response.",
            "impact": "An authenticated user may access another user's object by changing its identifier.",
            "remediation": "Authorize object ownership or access policy server-side for every object lookup; never trust client-supplied identifiers alone.",
            "evidence": responses,
        })
    return {"endpoint": endpoint, "objects": {"a": object_a, "b": object_b},
            "responses": responses, "bypasses": bypasses, "findings": findings}


def _workflow(session_a: requests.Session, session_b: requests.Session, base_url: str,
              endpoint: str, object_a: str, object_b: str, owner_a: str,
              owner_b: str, action: str, expected_a: bool, expected_b: bool) -> dict[str, Any]:
    cases = [
        ("a_own", session_a, object_a, owner_a, expected_a),
        ("a_other", session_a, object_b, owner_b, False),
        ("a_other_claim_a", session_a, object_b, owner_a, False),
        ("b_own", session_b, object_b, owner_b, expected_b),
        ("b_other", session_b, object_a, owner_a, False),
        ("b_other_claim_b", session_b, object_a, owner_b, False),
    ]
    responses, mismatches = {}, []
    for key, session, obj, owner, expected in cases:
        url = build_url(base_url, endpoint, object_id=obj, owner=owner, action=action)
        response = session.get(url, timeout=DEFAULT_TIMEOUT, allow_redirects=False)
        observed = decision(response)
        responses[key] = {"url": url, "expected": expected, "observed": observed, "fingerprint": fingerprint(response)}
        if observed is not None and observed != expected:
            mismatches.append(key)
    findings = []
    if mismatches:
        findings.append({
            "id": "P11-WORKFLOW-001",
            "title": "Authenticated workflow authorization differs from expected ownership decision",
            "severity": "High",
            "confidence": "High",
            "category": "Authorization / Business Workflow",
            "cwe": "CWE-862",
            "owasp": "API5:2023 Broken Function Level Authorization",
            "method": "GET",
            "url": responses[mismatches[0]]["url"],
            "detail": "The explicit workflow authorization decision did not match the operator-supplied expected decision.",
            "impact": "A user may be able to reach a workflow action for an object or owner they should not control.",
            "remediation": "Authorize the authenticated principal, object owner and workflow state together on the server.",
            "evidence": responses,
        })
    return {"endpoint": endpoint, "action": action, "responses": responses,
            "mismatches": mismatches, "findings": findings}


def run_phase11(base_url: str, endpoints: list[str], login_path: str,
                user_a_env: str, pass_a_env: str, user_b_env: str, pass_b_env: str,
                object_a: str | None = None, object_b: str | None = None,
                owner_a: str | None = None, owner_b: str | None = None,
                action: str | None = None, workflow_endpoint: str | None = None,
                expected_a: bool = True, expected_b: bool = True,
                max_probes: int = 160, evidence_dir: str = "evidence") -> dict[str, Any]:
    if not endpoints:
        raise ValueError("At least one explicit API endpoint is required")
    if max_probes < 1 or max_probes > 300:
        raise ValueError("max_probes must be between 1 and 300")

    session_a = login_with_env(base_url, user_a_env, pass_a_env, login_path)
    session_b = login_with_env(base_url, user_b_env, pass_b_env, login_path)

    api_results, findings = [], []
    remaining = max_probes
    for endpoint in endpoints[:20]:
        if remaining <= 0:
            break
        result = _bounded_parameter_fuzz(session_a, base_url, endpoint, remaining)
        api_results.append(result)
        findings.extend(result["findings"])
        remaining -= len(result["probes"])

    method_results = [_method_differential(session_a, base_url, endpoint) for endpoint in endpoints[:10]]
    for item in method_results:
        findings.extend(item["findings"])

    bola_result = None
    if object_a and object_b:
        bola_endpoint = next((e for e in endpoints if "{id}" in e), None)
        if bola_endpoint:
            bola_result = _bola(session_a, session_b, base_url, bola_endpoint, object_a, object_b)
            findings.extend(bola_result["findings"])

    workflow_result = None
    if workflow_endpoint and all(x is not None for x in (object_a, object_b, owner_a, owner_b, action)):
        workflow_result = _workflow(
            session_a, session_b, base_url, workflow_endpoint,
            str(object_a), str(object_b), str(owner_a), str(owner_b),
            str(action), expected_a, expected_b,
        )
        findings.extend(workflow_result["findings"])

    evidence = {
        "phase": "11-deep-authenticated-assessment",
        "target": base_url,
        "api_results": api_results,
        "method_results": method_results,
        "bola": bola_result,
        "workflow": workflow_result,
        "findings": findings,
        "summary": {
            "api_endpoints_tested": len(api_results),
            "parameter_probes": sum(len(x["probes"]) for x in api_results),
            "method_endpoints": len(method_results),
            "bola_tested": bola_result is not None,
            "workflow_tested": workflow_result is not None,
            "findings": len(findings),
        },
        "safety": {
            "same_origin": True,
            "login_post_only": True,
            "application_methods": ["GET", "HEAD", "OPTIONS"],
            "redirects": False,
            "automatic_endpoint_discovery": False,
            "state_changing_application_requests": False,
            "credential_attack": False,
            "dos": False,
        },
    }
    Path(evidence_dir).mkdir(parents=True, exist_ok=True)
    Path(evidence_dir, "phase11_deep_authenticated.json").write_text(
        json.dumps(evidence, indent=2), encoding="utf-8"
    )
    return evidence
