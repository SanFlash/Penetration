"""Phase 10 controlled authenticated authorization correlation assessment."""
from __future__ import annotations
import hashlib
import os
from urllib.parse import quote, urljoin
import requests
from utils.scope import assert_same_target

def _fingerprint(response):
    body = response.content[:200000]
    return {"status": response.status_code, "bytes": len(response.content),
            "content_type": response.headers.get("Content-Type", ""),
            "sha256": hashlib.sha256(body).hexdigest()}

def _decision(response):
    try: data = response.json()
    except ValueError: return None
    if isinstance(data, dict):
        for key in ("allowed", "authorized", "permitted"):
            if isinstance(data.get(key), bool): return data[key]
        nested = data.get("decision")
        if isinstance(nested, dict):
            for key in ("allowed", "authorized", "permitted"):
                if isinstance(nested.get(key), bool): return nested[key]
    return None

def _build_url(base_url, endpoint_template, object_id, owner, action):
    if not endpoint_template.startswith("/"): raise ValueError("endpoint must be an absolute path")
    for placeholder in ("{id}", "{owner}", "{action}"):
        if placeholder not in endpoint_template: raise ValueError(f"endpoint must contain {placeholder}")
    path = endpoint_template.format(id=quote(str(object_id), safe=""),
                                    owner=quote(str(owner), safe=""),
                                    action=quote(str(action), safe=""))
    url = urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
    assert_same_target(base_url, url)
    return url

def login_with_env(base_url, user_env, pass_env, login_path="/login"):
    username, password = os.getenv(user_env), os.getenv(pass_env)
    if not username or not password: raise RuntimeError(f"Missing credentials in {user_env}/{pass_env}")
    if not login_path.startswith("/"): raise ValueError("login_path must begin with '/'")
    login_url = urljoin(base_url.rstrip("/") + "/", login_path.lstrip("/"))
    assert_same_target(base_url, login_url)
    session = requests.Session()
    session.headers.update({"User-Agent": "Sentinel-Phase10-AuthzCorrelation/1.0"})
    response = session.post(login_url, data={"username": username, "password": password},
                            timeout=10, allow_redirects=False)
    if response.status_code not in {200,201,202,204,302,303}:
        raise RuntimeError(f"Authentication failed: HTTP {response.status_code}")
    return session

def assess_correlation(session_a, session_b, base_url, endpoint_template,
                       object_a, object_b, owner_a, owner_b, action,
                       expected_owner_a_allowed, expected_owner_b_allowed):
    if object_a == object_b: raise ValueError("object IDs must differ")
    if owner_a == owner_b: raise ValueError("owner values must differ")
    cases = [
        ("a_own", session_a, object_a, owner_a, expected_owner_a_allowed),
        ("a_object_b", session_a, object_b, owner_b, False),
        ("a_object_b_claim_a", session_a, object_b, owner_a, False),
        ("b_own", session_b, object_b, owner_b, expected_owner_b_allowed),
        ("b_object_a", session_b, object_a, owner_a, False),
        ("b_object_a_claim_b", session_b, object_a, owner_b, False),
    ]
    responses, mismatches = {}, []
    for name, session, object_id, owner, expected in cases:
        url = _build_url(base_url, endpoint_template, object_id, owner, action)
        response = session.get(url, timeout=10, allow_redirects=False)
        observed = _decision(response)
        responses[name] = {"url": url, "object_id": object_id, "owner_value": owner,
                           "expected_allowed": expected, "observed_allowed": observed,
                           "fingerprint": _fingerprint(response)}
        if observed is not None and observed != expected: mismatches.append(name)
    findings = []
    if mismatches:
        findings.append({
            "id": "P10-AUTHZ-001", "title": "Potential authorization correlation bypass",
            "severity": "High", "confidence": "High",
            "category": "Authorization / Business Logic Correlation",
            "cwe": "CWE-862", "owasp": "API5:2023 Broken Function Level Authorization",
            "method": "GET", "url": responses[mismatches[0]]["url"],
            "detail": "A supplied identity/object/owner/action combination produced an authorization decision different from the operator-defined expectation.",
            "impact": "An authenticated user may bypass an authorization rule by combining otherwise valid identifiers or workflow inputs.",
            "remediation": "Derive authorization from the authenticated principal and server-side object/workflow state. Validate every authorization-sensitive parameter as one server-side policy decision.",
            "evidence": responses})
    return {"endpoint_template": endpoint_template,
            "object_ids": {"a": object_a, "b": object_b},
            "owner_values": {"a": owner_a, "b": owner_b}, "action": action,
            "responses": responses, "mismatches": mismatches, "findings": findings,
            "safety": {"method": "GET", "same_origin": True, "redirects": False,
                       "automatic_discovery": False, "state_changing": False}}
