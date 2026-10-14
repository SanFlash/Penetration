"""Explicit, honest coverage registry for Sentinel's automated assessment.

This registry describes execution coverage, not certification or proof of security.
A category only counts as engine-complete when all mapped phases actually completed.
"""
from __future__ import annotations

from typing import Any

# WSTG-oriented categories plus API-specific coverage. Phase names must match
# the orchestrator ledger in main.py. Empty phase lists mean manual-only.
COVERAGE_REGISTRY = [
    {"id": "WSTG-INFO", "standard": "OWASP WSTG v4.2", "name": "Information Gathering", "phases": ["route_discovery", "information_disclosure"], "manual": "Review business-specific endpoints and authenticated areas."},
    {"id": "WSTG-CONF", "standard": "OWASP WSTG v4.2", "name": "Configuration and Deployment", "phases": ["security_headers", "active_security", "deep_security"], "manual": "Review deployment secrets, infrastructure configuration, and TLS details not available to this runtime."},
    {"id": "WSTG-IDNT", "standard": "OWASP WSTG v4.2", "name": "Identity Management", "phases": ["authenticated_discovery", "input_validation"], "manual": "Requires authorized test identities and expected identity lifecycle."},
    {"id": "WSTG-ATHN", "standard": "OWASP WSTG v4.2", "name": "Authentication", "phases": ["authenticated_discovery", "active_security"], "manual": "MFA, recovery flows, and account enumeration require configured accounts and dedicated tests."},
    {"id": "WSTG-ATHZ", "standard": "OWASP WSTG v4.2", "name": "Authorization", "phases": ["api_surface", "aggressive_readonly", "input_validation"], "manual": "Strong IDOR and privilege testing requires multiple authorized roles and known access expectations."},
    {"id": "WSTG-SESS", "standard": "OWASP WSTG v4.2", "name": "Session Management", "phases": ["active_security", "authenticated_discovery"], "manual": "Logout invalidation and session rotation need authenticated state."},
    {"id": "WSTG-INPV", "standard": "OWASP WSTG v4.2", "name": "Input Validation", "phases": ["deep_security", "input_validation", "input_stress"], "manual": "Context-specific injection validation and stored behavior may require safe application fixtures."},
    {"id": "WSTG-ERRH", "standard": "OWASP WSTG v4.2", "name": "Error Handling", "phases": ["information_disclosure", "deep_security"], "manual": "Only errors observed by executed probes are covered."},
    {"id": "WSTG-CRYP", "standard": "OWASP WSTG v4.2", "name": "Cryptography", "phases": ["security_headers", "active_security"], "manual": "No TLS grade is implied unless a dedicated TLS tool ran."},
    {"id": "WSTG-BUSL", "standard": "OWASP WSTG v4.2", "name": "Business Logic", "phases": ["functional_testing", "input_validation"], "manual": "Domain-specific workflows, pricing, transactions, and replay behavior require a supplied test plan."},
    {"id": "WSTG-CLNT", "standard": "OWASP WSTG v4.2", "name": "Client-side Testing", "phases": ["ui_responsive", "functional_testing", "information_disclosure"], "manual": "Browser checks cover only discovered pages, executed viewports, and observed client behavior."},
    {"id": "WCAG-2.2-AA", "standard": "W3C WCAG 2.2", "name": "Web Accessibility (automated heuristics)", "phases": ["accessibility"], "manual": "Automated DOM/color checks are triage only; keyboard-only workflows, screen-reader output, focus order, zoom/reflow, and full WCAG conformance require manual and assistive-technology validation."},
    {"id": "WSTG-API", "standard": "OWASP WSTG v4.2 / API Security Top 10:2023", "name": "API Security", "phases": ["api_surface", "deep_security", "input_validation"], "manual": "Schema-based and role-aware API testing requires an API schema and authorized credentials."},
    {"id": "API-BOLA", "standard": "OWASP API Security Top 10:2023", "name": "Broken Object Level Authorization", "phases": ["api_surface", "aggressive_readonly"], "manual": "Cannot be conclusively tested without object identifiers and role expectations."},
    {"id": "API-PROPERTY", "standard": "OWASP API Security Top 10:2023", "name": "Broken Object Property Level Authorization", "phases": ["api_surface", "aggressive_readonly"], "manual": "Property-level authorization and mass-assignment risks require authorized identities, schema/property expectations, and safe test objects."},
    {"id": "API-BFLA", "standard": "OWASP API Security Top 10:2023", "name": "Broken Function Level Authorization", "phases": ["api_surface", "aggressive_readonly"], "manual": "Requires role-aware expected permissions."},
    {"id": "API-AUTH", "standard": "OWASP API Security Top 10:2023", "name": "Broken Authentication", "phases": ["active_security", "authenticated_discovery"], "manual": "Authentication strength and MFA require configured test accounts."},
    {"id": "API-RESOURCE", "standard": "OWASP API Security Top 10:2023", "name": "Unrestricted Resource Consumption", "phases": ["input_stress", "input_validation"], "manual": "Only conservative bounded requests are used; this is not a load or denial-of-service test."},
    {"id": "API-BUSINESS-FLOW", "standard": "OWASP API Security Top 10:2023", "name": "Unrestricted Access to Sensitive Business Flows", "phases": ["functional_testing", "input_validation"], "manual": "Business-flow abuse requires an owner-defined workflow, test data, expected state transitions, and approved rate limits."},
    {"id": "API-MISCONFIG", "standard": "OWASP API Security Top 10:2023", "name": "Security Misconfiguration", "phases": ["security_headers", "active_security", "api_surface"], "manual": "Infrastructure and gateway configuration may not be visible externally."},
    {"id": "API-INVENTORY", "standard": "OWASP API Security Top 10:2023", "name": "Improper Inventory Management", "phases": ["route_discovery", "api_surface", "information_disclosure"], "manual": "A complete API inventory requires owner-provided specifications and version lists."},
    {"id": "API-UNSAFE-CONSUMPTION", "standard": "OWASP API Security Top 10:2023", "name": "Unsafe Consumption of APIs", "phases": ["api_surface", "deep_security", "information_disclosure"], "manual": "Validating upstream trust, schema enforcement, and unsafe third-party API responses requires an integration inventory and controlled upstream fixtures."},
    {"id": "API-SSRF", "standard": "OWASP API Security Top 10:2023", "name": "Server-Side Request Forgery", "phases": ["input_validation", "input_stress"], "manual": "No internal network, metadata, or sensitive resource is accessed to prove SSRF."},
    {"id": "AUTH-ROLES", "standard": "Sentinel", "name": "Authenticated and Role-aware Coverage", "phases": ["authenticated_discovery", "authz_bola", "authz_correlation"], "manual": "Requires explicitly supplied test sessions for each role."},
    {"id": "UPLOAD", "standard": "Sentinel", "name": "File Upload and Download", "phases": ["api_surface", "functional_testing"], "manual": "Safe upload tests need identified upload routes and harmless test files."},
    {"id": "DEPENDENCY", "standard": "Sentinel", "name": "Dependency and Source Analysis", "phases": ["information_disclosure"], "manual": "A remote website scan cannot reliably audit server source dependencies; provide source code or SBOM and run a dedicated tool."},
    {"id": "LOGGING", "standard": "OWASP WSTG v4.2", "name": "Security Logging and Monitoring", "phases": [], "manual": "Manual/server-side review required; external black-box checks cannot prove logging completeness."},
    {"id": "WEBSOCKET", "standard": "Sentinel", "name": "WebSocket Security", "phases": ["api_surface"], "manual": "Only applicable when WebSocket endpoints are discovered and the scanner supports their protocol."},
    {"id": "SENTINEL-UIUX", "standard": "Sentinel", "name": "UI/UX, Responsive Layout and Browser Evidence", "phases": ["ui_responsive"], "manual": "Browser heuristics cover only visited pages and configured viewports; usability and visual design still need human review."},
    {"id": "SENTINEL-FUNCTIONAL", "standard": "Sentinel", "name": "Functional and Navigation Smoke Tests", "phases": ["functional_testing"], "manual": "Read-only link checks do not prove business workflows, transactions, or state changes."},
    {"id": "SENTINEL-INPUT-VALIDATION", "standard": "Sentinel", "name": "Valid/Invalid Input Validation", "phases": ["input_validation"], "manual": "Only discovered query parameters and bounded input classes are exercised; form submission and authenticated input paths are not implied."},
    {"id": "SENTINEL-INPUT-STRESS", "standard": "Sentinel", "name": "Bounded Input Stress and Boundary Cases", "phases": ["input_stress"], "manual": "This is conservative input robustness testing, not load testing, denial-of-service testing, or an availability guarantee."},
    {"id": "SENTINEL-RECON", "standard": "Sentinel", "name": "Web Crawler, Route and Technology Surface", "phases": ["route_discovery", "information_disclosure"], "manual": "JavaScript parsing and unauthenticated crawling cannot guarantee a complete route or technology inventory."},
    {"id": "SENTINEL-INFO-LEAK", "standard": "Sentinel", "name": "Information Disclosure and Exposed Artifacts", "phases": ["information_disclosure"], "manual": "Checks a bounded list of common paths and observed responses; no source repository or server filesystem access is implied."},
    {"id": "SENTINEL-SECURITY", "standard": "Sentinel", "name": "Security Headers and Deep Security Engine", "phases": ["security_headers", "active_security", "deep_security"], "manual": "External black-box checks cannot establish internal infrastructure, source-code, or full authentication security."},
    {"id": "SENTINEL-ZAP", "standard": "OWASP ZAP Baseline", "name": "ZAP Spider and Passive Scan", "phases": ["zap_spider", "zap_passive", "zap_alert_collection"], "manual": "Requires an external ZAP daemon, API key, and pre-scoped context. Active scan is disabled in this integration."},
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
                "At least one mapped phase failed, timed out, or was blocked; this is not proof that the category is secure."
                if status == "partial_or_failed" else
                "Mapped phases were not executed in this assessment."
                if status == "not_run" else
                "Some mapped phases ran, but coverage is incomplete."
            ),
        })
    return rows
