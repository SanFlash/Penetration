"""Explicit, honest coverage registry for Sentinel's automated assessment.

This registry describes execution coverage, not certification or proof of security.
A category only counts as engine-complete when all mapped phases actually completed.
"""
from __future__ import annotations

from typing import Any

# WSTG-oriented categories plus API-specific coverage. Phase names must match
# the orchestrator ledger in main.py. Empty phase lists mean manual-only.
COVERAGE_REGISTRY = [
    {"id": "WSTG-INFO", "standard": "OWASP WSTG", "name": "Information Gathering", "phases": ["route_discovery", "information_disclosure"], "manual": "Review business-specific endpoints and authenticated areas."},
    {"id": "WSTG-CONF", "standard": "OWASP WSTG", "name": "Configuration and Deployment", "phases": ["security_headers", "active_security", "deep_security"], "manual": "Review deployment secrets, infrastructure configuration, and TLS details not available to this runtime."},
    {"id": "WSTG-IDNT", "standard": "OWASP WSTG", "name": "Identity Management", "phases": ["authenticated_discovery", "input_validation"], "manual": "Requires authorized test identities and expected identity lifecycle."},
    {"id": "WSTG-ATHN", "standard": "OWASP WSTG", "name": "Authentication", "phases": ["authenticated_discovery", "active_security"], "manual": "MFA, recovery flows, and account enumeration require configured accounts and dedicated tests."},
    {"id": "WSTG-ATHZ", "standard": "OWASP WSTG", "name": "Authorization", "phases": ["api_surface", "aggressive_readonly", "input_validation"], "manual": "Strong IDOR and privilege testing requires multiple authorized roles and known access expectations."},
    {"id": "WSTG-SESS", "standard": "OWASP WSTG", "name": "Session Management", "phases": ["active_security", "authenticated_discovery"], "manual": "Logout invalidation and session rotation need authenticated state."},
    {"id": "WSTG-INPV", "standard": "OWASP WSTG", "name": "Input Validation", "phases": ["deep_security", "input_validation", "input_stress"], "manual": "Context-specific injection validation and stored behavior may require safe application fixtures."},
    {"id": "WSTG-ERRH", "standard": "OWASP WSTG", "name": "Error Handling", "phases": ["information_disclosure", "deep_security"], "manual": "Only errors observed by executed probes are covered."},
    {"id": "WSTG-CRYP", "standard": "OWASP WSTG", "name": "Cryptography", "phases": ["security_headers", "active_security"], "manual": "No TLS grade is implied unless a dedicated TLS tool ran."},
    {"id": "WSTG-BUSL", "standard": "OWASP WSTG", "name": "Business Logic", "phases": ["functional_testing", "input_validation"], "manual": "Domain-specific workflows, pricing, transactions, and replay behavior require a supplied test plan."},
    {"id": "WSTG-CLNT", "standard": "OWASP WSTG", "name": "Client-side Testing", "phases": ["ui_responsive", "functional_testing", "information_disclosure"], "manual": "Browser checks cover only discovered pages, executed viewports, and observed client behavior."},
    {"id": "WSTG-API", "standard": "OWASP WSTG / API Top 10", "name": "API Security", "phases": ["api_surface", "deep_security", "input_validation"], "manual": "Schema-based and role-aware API testing requires an API schema and authorized credentials."},
    {"id": "API-BOLA", "standard": "OWASP API Security Top 10", "name": "Broken Object Level Authorization", "phases": ["api_surface", "aggressive_readonly"], "manual": "Cannot be conclusively tested without object identifiers and role expectations."},
    {"id": "API-BFLA", "standard": "OWASP API Security Top 10", "name": "Broken Function Level Authorization", "phases": ["api_surface", "aggressive_readonly"], "manual": "Requires role-aware expected permissions."},
    {"id": "API-AUTH", "standard": "OWASP API Security Top 10", "name": "Broken Authentication", "phases": ["active_security", "authenticated_discovery"], "manual": "Authentication strength and MFA require configured test accounts."},
    {"id": "API-RESOURCE", "standard": "OWASP API Security Top 10", "name": "Unrestricted Resource Consumption", "phases": ["input_stress", "input_validation"], "manual": "Only conservative bounded requests are used; this is not a load or denial-of-service test."},
    {"id": "API-MISCONFIG", "standard": "OWASP API Security Top 10", "name": "Security Misconfiguration", "phases": ["security_headers", "active_security", "api_surface"], "manual": "Infrastructure and gateway configuration may not be visible externally."},
    {"id": "API-INVENTORY", "standard": "OWASP API Security Top 10", "name": "Improper Inventory Management", "phases": ["route_discovery", "api_surface", "information_disclosure"], "manual": "A complete API inventory requires owner-provided specifications and version lists."},
    {"id": "API-SSRF", "standard": "OWASP API Security Top 10", "name": "Server-Side Request Forgery", "phases": ["input_validation", "input_stress"], "manual": "No internal network, metadata, or sensitive resource is accessed to prove SSRF."},
    {"id": "AUTH-ROLES", "standard": "Sentinel", "name": "Authenticated and Role-aware Coverage", "phases": ["authenticated_discovery", "authz_bola", "authz_correlation"], "manual": "Requires explicitly supplied test sessions for each role."},
    {"id": "UPLOAD", "standard": "Sentinel", "name": "File Upload and Download", "phases": ["api_surface", "functional_testing"], "manual": "Safe upload tests need identified upload routes and harmless test files."},
    {"id": "DEPENDENCY", "standard": "Sentinel", "name": "Dependency and Source Analysis", "phases": ["information_disclosure"], "manual": "A remote website scan cannot reliably audit server source dependencies; provide source code or SBOM and run a dedicated tool."},
    {"id": "LOGGING", "standard": "OWASP WSTG", "name": "Security Logging and Monitoring", "phases": [], "manual": "Manual/server-side review required; external black-box checks cannot prove logging completeness."},
    {"id": "WEBSOCKET", "standard": "Sentinel", "name": "WebSocket Security", "phases": ["api_surface"], "manual": "Only applicable when WebSocket endpoints are discovered and the scanner supports their protocol."},
]


def build_coverage_registry(phase_status: dict[str, Any] | None) -> list[dict[str, Any]]:
    """Resolve each coverage row against the real phase ledger."""
    ledger = phase_status or {}
    rows: list[dict[str, Any]] = []
    for definition in COVERAGE_REGISTRY:
        phase_rows = []
        for phase_name in definition["phases"]:
            phase = ledger.get(phase_name)
            phase = phase if isinstance(phase, dict) else {}
            phase_rows.append({
                "name": phase_name,
                "status": str(phase.get("status", "not_run")).lower(),
                "checks": phase.get("checks"),
                "error": phase.get("error"),
            })
        states = [row["status"] for row in phase_rows]
        if not states:
            status = "manual_review"
        elif all(state == "completed" for state in states):
            status = "engines_completed"
        elif all(state == "not_run" for state in states):
            status = "not_run"
        elif any(state in {"failed", "timed_out", "blocked"} for state in states):
            status = "partial_or_failed"
        elif any(state in {"completed", "partial"} for state in states):
            status = "partial"
        else:
            status = "not_run"
        rows.append({
            **definition,
            "status": status,
            "phase_results": phase_rows,
            "execution_note": (
                "Mapped phases completed; this is not proof that the category is secure."
                if status == "engines_completed" else
                "No mapped automated phase is configured for this category; manual review is required."
                if status == "manual_review" else
                "At least one mapped phase failed, timed out, or was blocked."
                if status == "partial_or_failed" else
                "Mapped phases were not executed in this assessment."
                if status == "not_run" else
                "Some mapped phases ran, but coverage is incomplete."
            ),
        })
    return rows
