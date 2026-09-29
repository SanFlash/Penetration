"""Bounded authenticated business-workflow authorization assessment.

This phase checks one explicitly selected workflow-action decision endpoint using
two disposable accounts and objects. The workflow endpoint itself is GET-only
and no state-changing action is invoked.

Detection prefers an explicit authorization decision such as allowed=true and
falls back to response fingerprint comparison when no decision field exists.
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


def _extract_authorization_decision(response: requests.Response) -> bool | None:
    """Return an explicit authorization decision when the response exposes one."""
    if "json" not in response.headers.get("Content-Type", "").lower():
        return None
    try:
        payload: Any = response.json()
    except (ValueError, TypeError):
        return None
    if not isinstance(payload, dict):
        return None

    for key in ("allowed", "authorized", "permitted"):
        decision = payload.get(key)
        if isinstance(decision, bool):
            return decision

    nested = payload.get("decision")
    if isinstance(nested, dict):
        for key in ("allowed", "authorized", "permitted"):
            decision = nested.get(key)
            if isinstance(decision, bool):
                return decision
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
    session.headers.update({"User-Agent": "Sentinel-Phase8-WorkflowAuth/1.1"})
    response = session.post(
        login_url,
        data={"username": username, "password": password},
        timeout=10,
        allow_redirects=False,
    )
    if response.status_code not in ALLOWED_LOGIN_STATUSES:
        raise RuntimeError(f"Authentication failed: HTTP {response.status_code}")
    return session


def _request_workflow(session: requests.Session, url: str) -> requests.Response:
    return session.get(url, timeout=10, allow_redirects=False)


def _cross_account_match(owner_response, cross_response) -> tuple[bool, str]:
    """Prefer semantic authorization decisions; use fingerprint only as fallback."""
    owner_decision = _extract_authorization_decision(owner_response)
    cross_decision = _extract_authorization_decision(cross_response)

    if owner_decision is not None or cross_decision is not None:
        return (
            owner_response.status_code == 200
            and cross_response.status_code == 200
            and owner_decision is True
            and cross_decision is True,
            "semantic",
        )

    owner_fp = _fingerprint(owner_response)
    cross_fp = _fingerprint(cross_response)
    return (
        owner_response.status_code == 200
        and cross_response.status_code == 200
        and owner_fp["sha256"] == cross_fp["sha256"]
        and owner_fp["bytes"] == cross_fp["bytes"],
        "fingerprint",
    )


def compare_workflow_action(
    session_a,
    session_b,
    base_url,
    endpoint_template,
    object_a,
    object_b,
    action,
):
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
    raw_responses = {}
    for key, (session, url) in requests_map.items():
        response = _request_workflow(session, url)
        raw_responses[key] = response
        responses[key] = {
            "url": url,
            "fingerprint": _fingerprint(response),
            "authorization_decision": _extract_authorization_decision(response),
        }

    a_to_b, a_mode = _cross_account_match(raw_responses["b_owned"], raw_responses["a_other"])
    b_to_a, b_mode = _cross_account_match(raw_responses["a_owned"], raw_responses["b_other"])

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
            "detail": (
                "A disposable cross-account workflow request received the same "
                "authorized action decision as the owning account."
            ),
            "impact": (
                "An authenticated user may be able to invoke or preview a "
                "workflow action for another user's object."
            ),
            "remediation": (
                "Authorize every business action against both the authenticated "
                "principal and the current server-side workflow state; do not "
                "trust object or action identifiers supplied by the client."
            ),
            "evidence": responses,
            "detection_mode": "semantic" if "semantic" in {a_mode, b_mode} else "fingerprint",
        })

    return {
        "endpoint_template": endpoint_template,
        "objects": {"a": object_a, "b": object_b},
        "action": action,
        "responses": responses,
        "cross_account_match": {"a_to_b": a_to_b, "b_to_a": b_to_a},
        "detection": {"a_to_b": a_mode, "b_to_a": b_mode},
        "findings": findings,
        "safety": {
            "workflow_method": "GET",
            "same_origin": True,
            "redirects": False,
            "automatic_discovery": False,
            "state_changing_requests": False,
        },
    }
