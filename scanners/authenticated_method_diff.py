"""Bounded authenticated HTTP-method differential testing.

Tests one explicitly selected object endpoint with two disposable accounts.
GET is the authorization baseline; HEAD is checked for a possible read-only
authorization bypass. OPTIONS is recorded as an exposure observation only.
"""
from __future__ import annotations

import hashlib
import os
from urllib.parse import urljoin

import requests

from utils.scope import assert_same_target


def _fingerprint(response: requests.Response) -> dict:
    body = response.content[:200000]
    return {
        "status": response.status_code,
        "bytes": len(response.content),
        "content_type": response.headers.get("Content-Type", ""),
        "allow": response.headers.get("Allow", ""),
        "sha256": hashlib.sha256(body).hexdigest(),
    }


def _build_url(base_url: str, endpoint_template: str, object_id: str) -> str:
    if not endpoint_template.startswith("/") or "{id}" not in endpoint_template:
        raise ValueError("endpoint must be an absolute path containing {id}")
    url = urljoin(
        base_url.rstrip("/") + "/",
        endpoint_template.format(id=object_id).lstrip("/"),
    )
    assert_same_target(base_url, url)
    return url


def login_with_env(base_url: str, user_env: str, pass_env: str, login_path: str = "/login") -> requests.Session:
    username, password = os.getenv(user_env), os.getenv(pass_env)
    if not username or not password:
        raise RuntimeError(f"Missing credentials in {user_env}/{pass_env}")
    if not login_path.startswith("/"):
        raise ValueError("login_path must begin with '/'")
    login_url = urljoin(base_url.rstrip("/") + "/", login_path.lstrip("/"))
    assert_same_target(base_url, login_url)
    session = requests.Session()
    session.headers.update({"User-Agent": "Sentinel-Phase7-MethodDiff/1.0"})
    response = session.post(
        login_url,
        data={"username": username, "password": password},
        timeout=10,
        allow_redirects=False,
    )
    if response.status_code not in {200, 201, 202, 204, 302, 303}:
        raise RuntimeError(f"Authentication failed: HTTP {response.status_code}")
    return session


def _request(session: requests.Session, method: str, url: str) -> requests.Response:
    if method not in {"GET", "HEAD", "OPTIONS"}:
        raise ValueError("only GET, HEAD and OPTIONS are permitted")
    return session.request(method, url, timeout=10, allow_redirects=False)


def compare_methods(session_a, session_b, base_url, endpoint_template, object_a, object_b) -> dict:
    if not object_a or not object_b:
        raise ValueError("object IDs are required")
    if object_a == object_b:
        raise ValueError("object IDs must differ")

    urls = {
        "a_object": _build_url(base_url, endpoint_template, object_a),
        "b_object": _build_url(base_url, endpoint_template, object_b),
    }
    sessions = {"a": session_a, "b": session_b}
    request_map = {
        "a_get_a": ("a", "GET", urls["a_object"]),
        "a_head_a": ("a", "HEAD", urls["a_object"]),
        "a_options_a": ("a", "OPTIONS", urls["a_object"]),
        "a_get_b": ("a", "GET", urls["b_object"]),
        "a_head_b": ("a", "HEAD", urls["b_object"]),
        "a_options_b": ("a", "OPTIONS", urls["b_object"]),
        "b_get_b": ("b", "GET", urls["b_object"]),
        "b_head_b": ("b", "HEAD", urls["b_object"]),
        "b_options_b": ("b", "OPTIONS", urls["b_object"]),
        "b_get_a": ("b", "GET", urls["a_object"]),
        "b_head_a": ("b", "HEAD", urls["a_object"]),
        "b_options_a": ("b", "OPTIONS", urls["a_object"]),
    }

    responses = {}
    for key, (session_key, method, url) in request_map.items():
        response = _request(sessions[session_key], method, url)
        responses[key] = {"method": method, "url": url, "fingerprint": _fingerprint(response)}

    a_get_other = responses["a_get_b"]["fingerprint"]
    a_head_other = responses["a_head_b"]["fingerprint"]
    b_get_other = responses["b_get_a"]["fingerprint"]
    b_head_other = responses["b_head_a"]["fingerprint"]

    a_head_bypass = a_get_other["status"] != 200 and a_head_other["status"] == 200
    b_head_bypass = b_get_other["status"] != 200 and b_head_other["status"] == 200

    findings = []
    if a_head_bypass or b_head_bypass:
        findings.append({
            "id": "P7-METHOD-001",
            "title": "Potential HEAD authorization bypass",
            "severity": "High",
            "confidence": "Medium",
            "category": "Authorization / HTTP Method Differential",
            "cwe": "CWE-862",
            "owasp": "API5:2023 Broken Function Level Authorization",
            "method": "HEAD",
            "url": urls["b_object"] if a_head_bypass else urls["a_object"],
            "detail": "GET denied the cross-account request while HEAD returned HTTP 200 for the same disposable object.",
            "impact": "An alternate read-only HTTP method may bypass an endpoint authorization control.",
            "remediation": "Apply the same authorization policy to every supported HTTP method and reject unsupported methods explicitly.",
            "evidence": {
                "a_get_other": responses["a_get_b"],
                "a_head_other": responses["a_head_b"],
                "b_get_other": responses["b_get_a"],
                "b_head_other": responses["b_head_a"],
            },
        })

    observations = []
    for key in ("a_options_a", "a_options_b", "b_options_b", "b_options_a"):
        allow = responses[key]["fingerprint"]["allow"]
        if allow:
            observations.append({
                "id": "P7-OBS-001",
                "type": "OPTIONS Allow header",
                "method": "OPTIONS",
                "url": responses[key]["url"],
                "allow": allow,
            })

    return {
        "endpoint_template": endpoint_template,
        "objects": {"a": object_a, "b": object_b},
        "responses": responses,
        "head_authorization_bypass": {"a_to_b": a_head_bypass, "b_to_a": b_head_bypass},
        "observations": observations,
        "findings": findings,
        "safety": {
            "methods": ["GET", "HEAD", "OPTIONS"],
            "same_origin": True,
            "redirects": False,
            "automatic_discovery": False,
            "state_changing_requests": False,
        },
    }
