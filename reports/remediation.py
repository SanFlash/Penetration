"""Structured remediation guidance for assessment findings.

The scanner remains evidence-first: these helpers enrich report presentation
without changing severity or claiming exploitability.
"""
from __future__ import annotations

from collections import Counter

CATEGORY_FIXES = {
    "cors": ("Use an explicit allowlist of trusted origins. Avoid reflecting arbitrary Origin values.",
             "Verify credentialed cross-origin requests from an untrusted origin are rejected."),
    "transport security": ("Serve application resources exclusively over HTTPS and enable HSTS where appropriate.",
                           "Reload affected HTTPS pages and confirm no active HTTP resources remain."),
    "session management": ("Harden authentication/session cookies with Secure, HttpOnly and an appropriate SameSite policy.",
                            "Inspect Set-Cookie responses and verify the intended flags are present."),
    "input validation": ("Validate input at the server boundary and apply context-specific output encoding before rendering.",
                          "Repeat the same inert mutation and verify the signal is no longer present."),
    "error handling": ("Return generic production errors and keep stack traces/debug output out of public responses.",
                       "Request a controlled invalid path and verify implementation details are no longer exposed."),
    "configuration": ("Disable unnecessary HTTP methods and server metadata in production.",
                      "Repeat the OPTIONS/response-header checks and confirm only required methods/metadata remain."),
    "api security": ("Document and enforce authentication and authorization requirements on every sensitive API operation.",
                     "Re-run API inventory and verify sensitive operations have explicit security requirements."),
}

def enrich_finding(finding: dict) -> dict:
    item = dict(finding)
    category = str(item.get("category", "")).strip().lower()
    default_fix, default_validation = CATEGORY_FIXES.get(
        category,
        ("Review the affected control, apply least-privilege/security-by-default behavior, and retest the exact evidence condition.",
         "Re-run the affected check and confirm the original evidence condition is no longer reproduced."),
    )
    item.setdefault("fix_summary", item.get("remediation") or default_fix)
    item.setdefault("validation_steps", default_validation)
    item.setdefault("remediation_priority", {
        "Critical": "Immediate", "High": "High", "Medium": "Planned",
        "Low": "Backlog", "Info": "Review",
    }.get(str(item.get("severity", "Info")), "Review"))
    item.setdefault("impact", "Security impact requires validation in the authorized application context.")
    return item

def build_remediation_summary(findings: list[dict]) -> dict:
    enriched = [enrich_finding(f) for f in findings]
    priority = Counter(f.get("remediation_priority", "Review") for f in enriched)
    actions, seen = [], set()
    severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
    for finding in sorted(enriched, key=lambda x: (severity_order.get(x.get("severity", "Info"), 9), x.get("title", ""))):
        key = (finding.get("title"), finding.get("category"))
        if key in seen:
            continue
        seen.add(key)
        actions.append({
            "title": finding.get("title", "Untitled finding"),
            "severity": finding.get("severity", "Info"),
            "category": finding.get("category", "Uncategorized"),
            "impact": finding.get("impact", ""),
            "fix": finding.get("fix_summary", finding.get("remediation", "")),
            "validation": finding.get("validation_steps", ""),
            "affected_urls": len(finding.get("affected_urls") or ([finding.get("url")] if finding.get("url") else [])),
            "observations": int(finding.get("observation_count", finding.get("occurrences", 1)) or 1),
        })
    return {"priority_counts": dict(priority), "actions": actions[:25]}
