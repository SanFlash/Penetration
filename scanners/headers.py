"""
scanners/headers.py — safe, read-only security header scanner.

Sends one GET request per URL and reports which standard security headers
are present or missing. Never modifies anything server-side.
"""
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
            "url": url,
            "detail": f"Missing: {', '.join(missing)}",
        })

    return {
        "url": url,
        "status_code": resp.status_code,
        "headers_present": present,
        "headers_missing": missing,
        "server_banner": resp.headers.get("Server", "not disclosed"),
        "findings": findings,
    }
