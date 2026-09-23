"""
scanners/idor_probe.py — horizontal authorization (IDOR/BOLA) probe.

Implements exactly the pattern taught in the companion manual (Chapter 16 /
Figure 8): as one authenticated user, request an object you own, then an
adjacent object ID you don't own, and compare the authorization outcome. A
200 OK on the second request where a 403 was expected is the finding.
"""
from utils.scope import assert_in_scope


def probe_endpoint(session, base_url: str, endpoint_template: str,
                    owned_id: int, other_id: int) -> dict:
    """
    endpoint_template example: "/api/orders/{id}"
    """
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
            "url": other_url,
            "detail": (
                f"Requesting object id={other_id} (not owned by the "
                f"authenticated user) returned {other_resp.status_code} with "
                f"body: {other_resp.text[:200]}. Expected 403/404. Compare "
                f"against the owned-object request to {owned_url}, which "
                f"correctly returned {owned_resp.status_code}."
            ),
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
