"""Controlled authenticated authorization/BOLA checks for disposable test data."""
from __future__ import annotations
import hashlib, json, os
from urllib.parse import urljoin, urlparse
import requests
from utils.scope import assert_same_target

def _fingerprint(response):
    body = response.content[:200000]
    return {"status": response.status_code, "bytes": len(response.content),
            "sha256": hashlib.sha256(body).hexdigest(),
            "content_type": response.headers.get("Content-Type", "")}

def _safe_url(base_url, template, object_id):
    if not template.startswith("/") or "{id}" not in template:
        raise ValueError("endpoint template must be an absolute path containing {id}")
    url = urljoin(base_url.rstrip("/") + "/", template.format(id=object_id).lstrip("/"))
    assert_same_target(base_url, url)
    return url

def login_with_env(base_url, user_env, pass_env, login_path="/login"):
    username, password = os.getenv(user_env), os.getenv(pass_env)
    if not username or not password:
        raise RuntimeError(f"Missing credentials in {user_env}/{pass_env}")
    if not login_path.startswith("/"):
        raise ValueError("login_path must begin with '/'")
    login_url = urljoin(base_url.rstrip("/") + "/", login_path.lstrip("/"))
    assert_same_target(base_url, login_url)
    session = requests.Session()
    session.headers.update({"User-Agent": "Sentinel-Phase4-AuthZ/1.0"})
    response = session.post(login_url, data={"username": username, "password": password},
                            timeout=10, allow_redirects=False)
    if response.status_code not in {200, 201, 202, 204, 302, 303}:
        raise RuntimeError(f"Authentication failed: HTTP {response.status_code}")
    return session

def compare_access(session_a, session_b, base_url, endpoint_template, object_a, object_b):
    urls = {
        "a_owned": _safe_url(base_url, endpoint_template, object_a),
        "a_other": _safe_url(base_url, endpoint_template, object_b),
        "b_owned": _safe_url(base_url, endpoint_template, object_b),
        "b_other": _safe_url(base_url, endpoint_template, object_a),
    }
    sessions = {"a_owned": session_a, "a_other": session_a,
                "b_owned": session_b, "b_other": session_b}
    responses = {}
    for key, url in urls.items():
        response = sessions[key].get(url, timeout=10, allow_redirects=False)
        responses[key] = {"url": url, "fingerprint": _fingerprint(response)}
    a_cross, b_owned = responses["a_other"]["fingerprint"], responses["b_owned"]["fingerprint"]
    b_cross, a_owned = responses["b_other"]["fingerprint"], responses["a_owned"]["fingerprint"]
    a_to_b = a_cross["status"] == 200 and a_cross["sha256"] == b_owned["sha256"] and a_cross["bytes"] == b_owned["bytes"]
    b_to_a = b_cross["status"] == 200 and b_cross["sha256"] == a_owned["sha256"] and b_cross["bytes"] == a_owned["bytes"]
    findings = []
    if a_to_b or b_to_a:
        findings.append({
            "id": "P4-BOLA-001", "title": "Potential broken object-level authorization",
            "severity": "High", "confidence": "High",
            "category": "Authorization / BOLA", "cwe": "CWE-639",
            "owasp": "API1:2023 Broken Object Level Authorization", "method": "GET",
            "url": urls["a_other"] if a_to_b else urls["b_other"],
            "detail": "A disposable object from another test account was accessible with a matching response fingerprint.",
            "impact": "An authenticated user may access another user's object by changing its identifier.",
            "remediation": "Enforce server-side authorization against the authenticated principal for every object access.",
            "evidence": json.dumps(responses, ensure_ascii=False),
        })
    return {"endpoint_template": endpoint_template, "objects": {"a": object_a, "b": object_b},
            "responses": responses, "cross_account_match": {"a_to_b": a_to_b, "b_to_a": b_to_a},
            "findings": findings}
