"""Horizontal authorization (IDOR/BOLA) probe."""
from utils.scope import assert_in_scope


def probe_endpoint(session, base_url: str, endpoint_template: str,
                   owned_id: int, other_id: int) -> dict:
    owned_url = base_url + endpoint_template.format(id=owned_id)
    other_url = base_url + endpoint_template.format(id=other_id)
    assert_in_scope(owned_url)
    assert_in_scope(other_url)

    owned_resp = session.get(owned_url, timeout=10)
    other_resp = session.get(other_url, timeout=10)
    vulnerable = other_resp.status_code == 200

    findings = []
    if vulnerable:
        findings.append({
            "id": f"IDOR-{other_id}",
            "title": f"Broken Object-Level Authorization at {endpoint_template}",
            "severity": "High",
            "confidence": "High",
            "category": "Authorization",
            "cwe": "CWE-639",
            "owasp": "A01:2021 Broken Access Control",
            "method": "GET",
            "url": other_url,
            "evidence": (
                f"Owned object id={owned_id} returned {owned_resp.status_code}; "
                f"non-owned object id={other_id} returned {other_resp.status_code}."
            ),
            "detail": (
                f"Requesting object id={other_id} for the authenticated user returned "
                f"{other_resp.status_code}. Expected 403/404 for an object owned by another user."
            ),
            "impact": "An authenticated user may access another user's object by changing an object identifier.",
            "remediation": "Enforce server-side object ownership or authorization checks on every object access. Never rely on identifier secrecy.",
            "references": ["https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/"],
        })

    return {
        "endpoint_template": endpoint_template,
        "owned_id": owned_id,
        "other_id": other_id,
        "owned_status": owned_resp.status_code,
        "other_status": other_resp.status_code,
        "vulnerable": vulnerable,
        "findings": findings,
    }
