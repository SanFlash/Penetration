"""Safe, read-only security header scanner."""
from utils.http_client import get

EXPECTED_HEADERS = [
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
]


def scan(url: str) -> dict:
    resp = get(url, tag="header_scan")
    present = {h: resp.headers[h] for h in EXPECTED_HEADERS if h in resp.headers}
    missing = [h for h in EXPECTED_HEADERS if h not in resp.headers]

    findings = []
    if missing:
        findings.append({
            "id": f"HDR-{abs(hash(url)) % 10000:04d}",
            "title": "Missing security headers",
            "severity": "Low" if len(missing) < 3 else "Medium",
            "confidence": "High",
            "category": "Security Configuration",
            "cwe": "CWE-693",
            "owasp": "A05:2021 Security Misconfiguration",
            "method": "GET",
            "url": url,
            "evidence": f"Missing headers: {', '.join(missing)}",
            "detail": f"Missing: {', '.join(missing)}",
            "impact": "Missing browser security controls can increase exposure to content injection, framing, MIME-sniffing, or referrer-related risks depending on application behavior.",
            "remediation": "Configure the appropriate response security headers for the application and verify them on all relevant responses.",
        })

    return {
        "url": url,
        "status_code": resp.status_code,
        "headers_present": present,
        "headers_missing": missing,
        "server_banner": resp.headers.get("Server", "not disclosed"),
        "findings": findings,
    }
