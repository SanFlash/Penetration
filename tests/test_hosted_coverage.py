"""Regression tests for hosted section-by-section coverage rendering."""
from web import _coverage_payload


def test_coverage_payload_separates_standards_and_preserves_execution_states():
    report = {
        "target": "https://example.test",
        "generated_at": "2026-10-14T08:00:00+00:00",
        "metadata": {
            "status": "PARTIAL",
            "phase_status": {
                "security_headers": {"status": "completed", "checks": 7},
                "active_security": {"status": "timed_out", "error": "budget reached"},
            },
        },
        "framework_coverage": [
            {
                "id": "WSTG-CONF", "standard": "OWASP WSTG v4.2",
                "name": "Configuration", "status": "partial_or_failed",
                "phase_results": [
                    {"name": "security_headers", "status": "completed", "checks": 7},
                    {"name": "active_security", "status": "timed_out", "error": "budget reached"},
                ],
                "manual": "Review infrastructure configuration.",
                "execution_note": "One mapped phase timed out.",
            },
            {
                "id": "API-BOLA", "standard": "OWASP API Security Top 10:2023",
                "name": "Broken Object Level Authorization", "status": "not_run",
                "phase_results": [{"name": "api_surface", "status": "not_run"}],
                "manual": "Requires authorized role accounts.",
            },
            {
                "id": "WCAG-2.2-AA", "standard": "W3C WCAG 2.2",
                "name": "Accessibility", "status": "manual_review",
                "phase_results": [{"name": "accessibility", "status": "not_run"}],
                "manual": "Assistive-technology review required.",
            },
            {
                "id": "AUTH-ROLES", "standard": "Sentinel",
                "name": "Role-aware Coverage", "status": "partial",
                "phase_results": [{"name": "authenticated_discovery", "status": "completed"}],
                "manual": "Provide authorized role sessions.",
            },
        ],
        "owasp_top10_2025_coverage": [
            {"code": "A05:2025", "name": "Injection", "status": "partial",
             "phases": [{"name": "input_validation", "status": "partial"}],
             "limitation": "Manual confirmation is required."}
        ],
        "owasp_coverage": [
            {"code": "A03:2021", "name": "Injection", "status": "engines_completed",
             "phases": [{"name": "deep_security", "status": "completed"}],
             "limitation": "Engine execution is not proof of security."}
        ],
    }

    payload = _coverage_payload(report)
    sections = {section["id"]: section for section in payload["sections"]}

    assert payload["ready"] is True
    assert payload["overall_status"] == "PARTIAL"
    assert set(sections) == {"wstg", "owasp-2025", "owasp-2021", "api-top10", "wcag", "supplemental"}
    assert sections["wstg"]["items"][0]["id"] == "WSTG-CONF"
    assert sections["api-top10"]["items"][0]["id"] == "API-BOLA"
    assert sections["wcag"]["items"][0]["id"] == "WCAG-2.2-AA"
    assert sections["owasp-2025"]["items"][0]["code"] == "A05:2025"
    assert sections["owasp-2021"]["items"][0]["code"] == "A03:2021"
    assert payload["summary"]["total_areas"] == 5
    assert payload["summary"]["partial_or_failed"] == 1
    assert payload["summary"]["partial"] == 2
    assert payload["summary"]["not_run"] == 1
    assert payload["summary"]["manual_review"] == 1


def test_empty_coverage_payload_marks_registered_areas_not_run():
    payload = _coverage_payload(None)

    assert payload["ready"] is False
    assert payload["summary"]["total_areas"] >= 20
    assert payload["summary"]["not_run"] == payload["summary"]["total_areas"]
    assert payload["summary"]["engines_completed"] == 0
    assert payload["summary"]["partial_or_failed"] == 0
    assert payload["summary"]["manual_review"] >= 1
    assert all(section["items"] for section in payload["sections"] if section["id"] in {"wstg", "api-top10", "wcag", "supplemental"})
