"""Reflected XSS probe using a benign, unique marker."""
import uuid

from utils.http_client import get

MARKER_TEMPLATE = "<xss-probe-{token}>"


def probe_param(base_url: str, param: str) -> dict:
    token = uuid.uuid4().hex[:8]
    marker = MARKER_TEMPLATE.format(token=token)
    url = f"{base_url}?{param}={marker}"
    resp = get(url, tag="xss_probe")

    reflected_unescaped = marker in resp.text
    reflected_escaped = marker.replace("<", "&lt;").replace(">", "&gt;") in resp.text

    findings = []
    if reflected_unescaped:
        findings.append({
            "id": f"XSS-{token}",
            "title": f"Reflected XSS in parameter '{param}'",
            "severity": "High",
            "confidence": "High",
            "category": "Injection",
            "cwe": "CWE-79",
            "owasp": "A03:2021 Injection",
            "method": "GET",
            "parameter": param,
            "url": url,
            "evidence": f"Marker {marker!r} was returned unescaped in the response body.",
            "detail": f"Marker '{marker}' was reflected without HTML encoding.",
            "impact": "If an attacker-controlled value is interpreted as active browser markup or script in the affected context, it can execute in a victim's browser.",
            "remediation": "Apply context-appropriate output encoding at the point where untrusted data is inserted into HTML. Use a safe templating context and validate input where appropriate.",
            "references": ["https://owasp.org/www-community/attacks/xss/"],
        })

    return {
        "url": url,
        "param": param,
        "marker": marker,
        "reflected_unescaped": reflected_unescaped,
        "reflected_escaped": reflected_escaped,
        "findings": findings,
    }
