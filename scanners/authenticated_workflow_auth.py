"""Bounded authenticated business-workflow authorization assessment.

This phase checks a read-only action-decision endpoint using two disposable
accounts, two disposable objects, and one explicitly selected action. It
compares the owning account's decision with the other account's decision.
No workflow mutation is performed.
"""
from __future__ import annotations

import hashlib
import os
from urllib.parse import quote, urljoin

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


def _build_url(base_url: str, endpoint_template: str, object_id: str, action: str) -> str:
    if not endpoint_template.startswith("/"):
        raise ValueError("endpoint must be an absolute path")
    if "{id}" not in endpoint_template or "{action}" not in endpoint_template:
        raise ValueError("endpoint must contain {id} and {action}")
    url = urljoin(
        base_url.rstrip("/") + "/",
        endpoint_template.format(id=quote(object_id, safe=""), action=quote(action, safe="")).lstrip("/"),
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
    session.headers.update({"User-Agent": "Sentinel-Phase8-WorkflowAuth/1.0"})
    response = session.post(login_url, data={"username": username, "password": password},
                            timeout=10, allow_redirects=False)
    if response.status_code not in {200, 201, 202, 204, 302, 303}:
        raise RuntimeError(f"Authentication failed: HTTP {response.status_code}")
    return session


def compare_workflow_action(session_a, session_b, base_url, endpoint_template, object_a, object_b, action):
    if not object_a or not object_b or not action:
        raise ValueError("object IDs and action are required")
    if object_a == object_b:
        raise ValueError("object IDs must differ")

    urls = {
        "a_owned": _build_url(base_url, endpoint_template, object_a, action),
        "a_other": _build_url(base_url, endpoint_template, object_b, action),
        "b_owned": _build_url(base_url, endpoint_template, object_b, action),
        "b_other": _build_url(base_url, endpoint_template, object_a, action),
    }
    requests_map = {
        "a_owned": (session_a, urls["a_owned"]),
        "a_other": (session_a, urls["a_other"]),
        "b_owned": (session_b, urls["b_owned"]),
        "b_other": (session_b, urls["b_other"]),
    }

    responses = {}
    for key, (session, url) in requests_map.items():
        response = session.get(url, timeout=10, allow_redirects=False)
        responses[key] = {"url": url, "fingerprint": _fingerprint(response)}

    a_owned = responses["a_owned"]["fingerprint"]
    a_other = responses["a_other"]["fingerprint"]
    b_owned = responses["b_owned"]["fingerprint"]
    b_other = responses["b_other"]["fingerprint"]

    a_to_b = a_other["status"] == 200 and a_other["sha256"] == b_owned["sha256"] and a_other["bytes"] == b_owned["bytes"]
    b_to_a = b_other["status"] == 200 and b_other["sha256"] == a_owned["sha256"] and b_other["bytes"] == a_owned["bytes"]

    findings = []
    if a_to_b or b_to_a:
        findings.append({
            "id": "P8-WORKFLOW-001",
            "title": "Potential cross-account business-workflow authorization bypass",
            "severity": "High",
            "confidence": "High",
            "category": "Authorization / Business Workflow",
            "cwe": "CWE-862",
            "owasp": "API5:2023 Broken Function Level Authorization",
            "method": "GET",
            "action": action,
            "url": urls["a_other"] if a_to_b else urls["b_other"],
            "detail": "A disposable cross-account workflow action returned a response matching the owning account's authorized action decision.",
            "impact": "An authenticated user may be able to invoke or preview a workflow action for another user's object.",
            "remediation": "Authorize every business action against both the authenticated principal and the current server-side workflow state; do not trust object or action identifiers supplied by the client.",
            "evidence": responses,
        })

    return {
        "endpoint_template": endpoint_template,
        "objects": {"a": object_a, "b": object_b},
        "action": action,
        "responses": responses,
        "cross_account_match": {"a_to_b": a_to_b, "b_to_a": b_to_a},
        "findings": findings,
        "safety": {
            "method": "GET",
            "same_origin": True,
            "redirects": False,
            "automatic_discovery": False,
            "state_changing_requests": False,
        },
    }
