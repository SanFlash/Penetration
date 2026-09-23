"""
scanners/sqli_probe.py — boolean-based SQL injection probe.

Uses only non-destructive payloads: a single quote (to trigger a syntax
error if input reaches the SQL layer unsanitized) and a true/false pair (to
compare response shape). It never sends payloads that write, alter, or
delete data (no DROP/INSERT/UPDATE/DELETE) — that distinction matters both
for safety and for staying within what a benign detection probe needs.
"""
from utils.http_client import get

# Payloads are appended to the baseline parameter value.
QUOTE_PAYLOAD = "'"
TRUE_PAYLOAD = "' OR '1'='1"
FALSE_PAYLOAD = "' AND '1'='2"


def probe_param(base_url: str, param: str, baseline_value: str = "test") -> dict:
    baseline = get(f"{base_url}?{param}={baseline_value}", tag="sqli_baseline")
    quote_resp = get(f"{base_url}?{param}={baseline_value}{QUOTE_PAYLOAD}", tag="sqli_quote")
    true_resp = get(f"{base_url}?{param}={baseline_value}{TRUE_PAYLOAD}", tag="sqli_true")
    false_resp = get(f"{base_url}?{param}={baseline_value}{FALSE_PAYLOAD}", tag="sqli_false")

    error_triggered = quote_resp.status_code >= 500 or "error" in quote_resp.text.lower()
    boolean_diff = (len(true_resp.text) != len(false_resp.text)) and (
        len(true_resp.text) != len(baseline.text) or len(false_resp.text) != len(baseline.text)
    )

    findings = []
    if error_triggered:
        findings.append({
            "id": f"SQLI-ERR-{abs(hash(base_url + param)) % 10000:04d}",
            "title": f"Possible SQL injection (error-based) in parameter '{param}'",
            "severity": "Critical",
            "url": f"{base_url}?{param}={baseline_value}{QUOTE_PAYLOAD}",
            "detail": (
                "A single quote caused a server error or an error-shaped "
                "response, suggesting the input reached the SQL layer "
                "unsanitized. Manually verify with Repeater before reporting."
            ),
        })
    if boolean_diff:
        findings.append({
            "id": f"SQLI-BOOL-{abs(hash(base_url + param)) % 10000:04d}",
            "title": f"Possible SQL injection (boolean-based) in parameter '{param}'",
            "severity": "Critical",
            "url": base_url,
            "detail": (
                f"'{param}' with an always-true condition returned a "
                f"different-length response than an always-false condition "
                f"({len(true_resp.text)} vs {len(false_resp.text)} bytes), "
                f"suggesting the WHERE clause's logic is directly influenced "
                f"by unsanitized input."
            ),
        })

    return {
        "param": param,
        "baseline_len": len(baseline.text),
        "quote_status": quote_resp.status_code,
        "true_len": len(true_resp.text),
        "false_len": len(false_resp.text),
        "error_triggered": error_triggered,
        "boolean_diff": boolean_diff,
        "findings": findings,
    }
