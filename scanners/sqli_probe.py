"""Non-destructive SQL injection detection probes."""
from utils.http_client import get

QUOTE_PAYLOAD = "'"
TRUE_PAYLOAD = "' OR '1'='1"
FALSE_PAYLOAD = "' AND '1'='2"


def probe_param(base_url: str, param: str, baseline_value: str = "test") -> dict:
    baseline = get(f"{base_url}?{param}={baseline_value}", tag="sqli_baseline")
    quote_resp = get(
        f"{base_url}?{param}={baseline_value}{QUOTE_PAYLOAD}", tag="sqli_quote"
    )
    true_resp = get(
        f"{base_url}?{param}={baseline_value}{TRUE_PAYLOAD}", tag="sqli_true"
    )
    false_resp = get(
        f"{base_url}?{param}={baseline_value}{FALSE_PAYLOAD}", tag="sqli_false"
    )

    error_triggered = (
        quote_resp.status_code >= 500 or "error" in quote_resp.text.lower()
    )
    boolean_diff = (len(true_resp.text) != len(false_resp.text)) and (
        len(true_resp.text) != len(baseline.text)
        or len(false_resp.text) != len(baseline.text)
    )

    findings = []
    if error_triggered:
        findings.append({
            "id": f"SQLI-ERR-{abs(hash(base_url + param)) % 10000:04d}",
            "title": f"Possible SQL injection (error-based) in parameter '{param}'",
            "severity": "Critical",
            "confidence": "Medium",
            "category": "Injection",
            "cwe": "CWE-89",
            "owasp": "A03:2021 Injection",
            "method": "GET",
            "parameter": param,
            "url": f"{base_url}?{param}={baseline_value}{QUOTE_PAYLOAD}",
            "evidence": (
                f"Baseline status={baseline.status_code}; quote status={quote_resp.status_code}. "
                f"The quote response contained an error signal: {error_triggered}."
            ),
            "detail": "A quote caused a server error or error-shaped response; this is a detection signal and should be manually verified before a production report labels it confirmed SQL injection.",
            "impact": "If confirmed, unsanitized SQL input can allow an attacker to alter query logic and access data beyond intended application behavior.",
            "remediation": "Use parameterized queries/prepared statements and avoid constructing SQL by concatenating untrusted input.",
            "references": ["https://owasp.org/www-community/attacks/SQL_Injection"],
        })
    if boolean_diff:
        findings.append({
            "id": f"SQLI-BOOL-{abs(hash(base_url + param)) % 10000:04d}",
            "title": f"Possible SQL injection (boolean-based) in parameter '{param}'",
            "severity": "Critical",
            "confidence": "Medium",
            "category": "Injection",
            "cwe": "CWE-89",
            "owasp": "A03:2021 Injection",
            "method": "GET",
            "parameter": param,
            "url": base_url,
            "evidence": (
                f"True response length={len(true_resp.text)}; false response length="
                f"{len(false_resp.text)}; baseline length={len(baseline.text)}."
            ),
            "detail": "The true/false probes produced different response shapes. This is a signal requiring verification, not proof by response length alone.",
            "impact": "If confirmed, unsanitized SQL input can alter database query logic.",
            "remediation": "Use parameterized queries/prepared statements and keep database errors out of user-facing responses.",
            "references": ["https://owasp.org/www-community/attacks/SQL_Injection"],
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
