"""Phase 9: authenticated business-workflow state/precondition assessment.

This phase evaluates one explicitly selected, read-only workflow decision
endpoint against two disposable objects representing two known workflow states.
The operator supplies the expected authorization decision for each object.

No state-changing request is made and the scanner does not attempt to transition
an object between states.
"""
from __future__ import annotations

import hashlib
import os
from typing import Any
from urllib.parse import quote, urljoin

import requests

from utils.scope import assert_same_target

MAX_BODY_BYTES = 200_000
ALLOWED_LOGIN_STATUSES = {200, 201, 202, 204, 302, 303}


def _fingerprint(response: requests.Response) -> dict:
    body = response.content[:MAX_BODY_BYTES]
    return {
        "status": response.status_code,
        "bytes": len(response.content),
        "content_type": response.headers.get("Content-Type", ""),
        "sha256": hashlib.sha256(body).hexdigest(),
    }


def _extract_decision(response: requests.Response) -> bool | None:
    if "json" not in response.headers.get("Content-Type", "").lower():
        return None
    try:
        payload: Any = response.json()
    except (ValueError, TypeError, AttributeError):
        return None
    if not isinstance(payload, dict):
        return None

    for key in ("allowed", "authorized", "permitted"):
        value = payload.get(key)
        if isinstance(value, bool):
            return value

    nested = payload.get("decision")
    if isinstance(nested, dict):
        for key in ("allowed", "authorized", "permitted"):
            value = nested.get(key)
            if isinstance(value, bool):
                return value
    return None


def _build_url(base_url: str, endpoint_template: str, object_id: str, action: str) -> str:
    if not endpoint_template.startswith("/"):
        raise ValueError("endpoint must be an absolute path")
    if "{id}" not in endpoint_template or "{action}" not in endpoint_template:
        raise ValueError("endpoint must contain {id} and {action}")

    url = urljoin(
        base_url.rstrip("/") + "/",
        endpoint_template.format(
            id=quote(object_id, safe=""),
            action=quote(action, safe=""),
        ).lstrip("/"),
    )
    assert_same_target(base_url, url)
    return url


def login_with_env(
    base_url: str,
    user_env: str,
    pass_env: str,
    login_path: str = "/login",
) -> requests.Session:
    username, password = os.getenv(user_env), os.getenv(pass_env)
    if not username or not password:
        raise RuntimeError(f"Missing credentials in {user_env}/{pass_env}")
    if not login_path.startswith("/"):
        raise ValueError("login_path must begin with '/'")

    login_url = urljoin(base_url.rstrip("/") + "/", login_path.lstrip("/"))
    assert_same_target(base_url, login_url)

    session = requests.Session()
    session.headers.update({"User-Agent": "Sentinel-Phase9-WorkflowState/1.0"})
    response = session.post(
        login_url,
        data={"username": username, "password": password},
        timeout=10,
        allow_redirects=False,
    )
    if response.status_code not in ALLOWED_LOGIN_STATUSES:
        raise RuntimeError(f"Authentication failed: HTTP {response.status_code}")
    return session


def assess_workflow_preconditions(
    session,
    base_url: str,
    endpoint_template: str,
    object_a: str,
    object_b: str,
    action: str,
    expected_a: bool,
    expected_b: bool,
    state_a: str,
    state_b: str,
) -> dict:
    if not object_a or not object_b or not action:
        raise ValueError("object IDs and action are required")
    if object_a == object_b:
        raise ValueError("object IDs must differ")
    if state_a == state_b:
        raise ValueError("state-a and state-b must differ for a differential check")

    urls = {
        "state_a": _build_url(base_url, endpoint_template, object_a, action),
        "state_b": _build_url(base_url, endpoint_template, object_b, action),
    }

    responses = {}
    raw = {}
    for key, url in urls.items():
        response = session.get(url, timeout=10, allow_redirects=False)
        raw[key] = response
        responses[key] = {
            "url": url,
            "workflow_state": state_a if key == "state_a" else state_b,
            "expected_allowed": expected_a if key == "state_a" else expected_b,
            "observed_allowed": _extract_decision(response),
            "fingerprint": _fingerprint(response),
        }

    mismatches = []
    for key, expected in (("state_a", expected_a), ("state_b", expected_b)):
        observed = responses[key]["observed_allowed"]
        if observed is not None and observed != expected:
            mismatches.append(key)

    findings = []
    if mismatches:
        first = mismatches[0]
        findings.append({
            "id": "P9-WORKFLOW-001",
            "title": "Workflow action does not enforce the expected state precondition",
            "severity": "High",
            "confidence": "High",
            "category": "Authorization / Business Workflow State",
            "cwe": "CWE-841",
            "owasp": "API6:2023 Unrestricted Access to Sensitive Business Flows",
            "method": "GET",
            "action": action,
            "url": responses[first]["url"],
            "detail": (
                "The selected workflow endpoint returned an authorization "
                "decision inconsistent with the operator-supplied expected "
                "decision for the known workflow state."
            ),
            "impact": (
                "A business action may be exposed outside its intended "
                "workflow state, allowing an authenticated user to reach an "
                "invalid or prematurely available workflow step."
            ),
            "remediation": (
                "Enforce workflow-state preconditions server-side for every "
                "business action. Derive the current state from trusted "
                "server-side data and reject actions that are not valid for "
                "that state; do not rely on client-supplied state values."
            ),
            "evidence": responses,
        })

    return {
        "endpoint_template": endpoint_template,
        "action": action,
        "objects": {
            "a": {"id": object_a, "known_state": state_a, "expected_allowed": expected_a},
            "b": {"id": object_b, "known_state": state_b, "expected_allowed": expected_b},
        },
        "responses": responses,
        "mismatches": mismatches,
        "findings": findings,
        "safety": {
            "method": "GET",
            "same_origin": True,
            "redirects": False,
            "automatic_discovery": False,
            "state_changing_requests": False,
            "operator_supplied_expected_state": True,
        },
    }
