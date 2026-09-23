"""
scanners/xss_probe.py — reflected XSS probe using a benign, unique marker.

Sends a harmless marker string (never a real <script> payload with side
effects) into a parameter and checks whether it comes back UNESCAPED in the
HTML response. This proves the vulnerability class without ever executing
attacker-controlled script content, which is unnecessary for detection and
would blur the line between "safe probe" and "exploit."
"""
import uuid

from utils.http_client import get

MARKER_TEMPLATE = '<xss-probe-{token}>'


def probe_param(base_url: str, param: str) -> dict:
    token = uuid.uuid4().hex[:8]
    marker = MARKER_TEMPLATE.format(token=token)
    url = f"{base_url}?{param}={marker}"
    resp = get(url, tag="xss_probe")

    reflected_unescaped = marker in resp.text
    reflected_escaped = (
        marker.replace("<", "&lt;").replace(">", "&gt;") in resp.text
    )

    findings = []
    if reflected_unescaped:
        findings.append({
            "id": f"XSS-{token}",
            "title": f"Reflected XSS in parameter '{param}'",
            "severity": "High",
            "url": url,
            "detail": (
                f"Marker '{marker}' was reflected in the response body "
                f"without HTML encoding. Any injected content here, not just "
                f"this benign marker, would execute in the victim's browser."
            ),
        })

    return {
        "url": url,
        "param": param,
        "marker": marker,
        "reflected_unescaped": reflected_unescaped,
        "reflected_escaped": reflected_escaped,
        "findings": findings,
    }
