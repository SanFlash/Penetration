"""Bounded authenticated GET-only parameter differential testing.

Tests one explicitly selected endpoint template with two disposable values
under two authenticated sessions. This phase never discovers or invokes
arbitrary candidates automatically; the operator must supply the endpoint and
parameter. It is intended for controlled authorization/parameter-tampering
checks after Phase 5 inventory.
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
        "sha256": hashlib.sha256(body).hexdigest(),
    }


def _build_url(base_url: str, endpoint_template: str, parameter: str, value: str) -> str:
    if not endpoint_template.startswith("/"):
        raise ValueError("endpoint must be an absolute path")
    placeholder = "{" + parameter + "}"
    if placeholder not in endpoint_template:
        raise ValueError(f"endpoint must contain {placeholder}")
    url = urljoin(base_url.rstrip("/") + "/", endpoint_template.format(**{parameter: value}).lstrip("/"))
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
    session.headers.update({"User-Agent": "Sentinel-Phase6-ParameterDiff/1.0"})
    response = session.post(login_url, data={"username": username, "password": password},
                            timeout=10, allow_redirects=False)
    if response.status_code not in {200, 201, 202, 204, 302, 303}:
        raise RuntimeError(f"Authentication failed: HTTP {response.status_code}")
    return session


def compare_parameter(
    session_a: requests.Session,
    session_b: requests.Session,
    base_url: str,
    endpoint_template: str,
    parameter: str,
    value_a: str,
    value_b: str,
) -> dict:
    if not parameter or any(x == "" for x in (value_a, value_b)):
        raise ValueError("parameter and values are required")
    if value_a == value_b:
        raise ValueError("values must differ")

    urls = {
        "a_value_a": _build_url(base_url, endpoint_template, parameter, value_a),
        "a_value_b": _build_url(base_url, endpoint_template, parameter, value_b),
        "b_value_b": _build_url(base_url, endpoint_template, parameter, value_b),
        "b_value_a": _build_url(base_url, endpoint_template, parameter, value_a),
    }
    sessions = {
        "a_value_a": session_a, "a_value_b": session_a,
        "b_value_b": session_b, "b_value_a": session_b,
    }
    responses = {}
    for key, url in urls.items():
        response = sessions[key].get(url, timeout=10, allow_redirects=False)
        responses[key] = {"url": url, "fingerprint": _fingerprint(response)}

    a_cross = responses["a_value_b"]["fingerprint"]
    b_owner = responses["b_value_b"]["fingerprint"]
    b_cross = responses["b_value_a"]["fingerprint"]
    a_owner = responses["a_value_a"]["fingerprint"]

    a_to_b = a_cross["status"] == 200 and a_cross["sha256"] == b_owner["sha256"] and a_cross["bytes"] == b_owner["bytes"]
    b_to_a = b_cross["status"] == 200 and b_cross["sha256"] == a_owner["sha256"] and b_cross["bytes"] == a_owner["bytes"]

    findings = []
    if a_to_b or b_to_a:
        findings.append({
            "id": "P6-PARAM-001",
            "title": "Potential authenticated parameter authorization bypass",
            "severity": "High",
            "confidence": "High",
            "category": "Authorization / Parameter Tampering",
            "cwe": "CWE-639",
            "owasp": "API1:2023 Broken Object Level Authorization",
            "method": "GET",
            "url": urls["a_value_b"] if a_to_b else urls["b_value_a"],
            "detail": "A disposable alternate parameter value produced a response matching the other account's authorized response.",
            "impact": "An authenticated user may obtain another user's object by changing an authorization-sensitive parameter.",
            "remediation": "Authorize the requested resource against the authenticated principal on the server; never trust client-supplied ownership identifiers.",
            "evidence": responses,
        })

    return {
        "endpoint_template": endpoint_template,
        "parameter": parameter,
        "values": {"a": value_a, "b": value_b},
        "responses": responses,
        "cross_account_match": {"a_to_b": a_to_b, "b_to_a": b_to_a},
        "findings": findings,
        "safety": {
            "method": "GET",
            "same_origin": True,
            "redirects": False,
            "automatic_discovery": False,
        },
    }
