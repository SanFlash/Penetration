from scanners.coverage_registry import build_coverage_registry


def test_coverage_registry_never_marks_missing_phases_as_complete():
    rows = build_coverage_registry({
        "security_headers": {"status": "completed"},
        "active_security": {"status": "timed_out"},
        "api_surface": {"status": "completed"},
        "deep_security": {"status": "completed"},
    })
    by_id = {row["id"]: row for row in rows}

    assert len(rows) >= 20
    assert by_id["WSTG-CONF"]["status"] == "partial_or_failed"
    assert by_id["API-MISCONFIG"]["status"] == "partial_or_failed"
    assert by_id["LOGGING"]["status"] == "manual_review"
    assert by_id["WSTG-ATHZ"]["status"] == "partial"
    assert "not proof" in by_id["WSTG-CONF"]["execution_note"]


def test_coverage_registry_preserves_per_phase_execution_status():
    rows = build_coverage_registry({
        "security_headers": {"status": "completed", "checks": 4},
        "active_security": {"status": "completed", "checks": 8},
        "deep_security": {"status": "not_run"},
    })
    by_id = {row["id"]: row for row in rows}

    config = by_id["WSTG-CONF"]
    assert config["status"] == "partial"
    assert [phase["status"] for phase in config["phase_results"]] == ["completed", "completed", "not_run"]
    assert config["phase_results"][0]["checks"] == 4
    assert "incomplete" in config["execution_note"]

def test_wcag_coverage_depends_on_accessibility_phase_execution():
    not_run = {row["id"]: row for row in build_coverage_registry({})}
    completed = {
        row["id"]: row for row in build_coverage_registry({
            "accessibility": {"status": "completed", "checks": 22, "browser_cases": 2}
        })
    }

    assert not_run["WCAG-2.2-AA"]["status"] == "not_run"
    assert completed["WCAG-2.2-AA"]["status"] == "engines_completed"
    assert "manual" in completed["WCAG-2.2-AA"]["manual"].lower()
    assert "not proof" in completed["WCAG-2.2-AA"]["execution_note"]

def test_api_security_top10_categories_are_explicit_and_not_overclaimed():
    rows = build_coverage_registry({})
    by_id = {row["id"]: row for row in rows}
    api_ids = {
        "API-BOLA", "API-PROPERTY", "API-AUTH", "API-RESOURCE",
        "API-BFLA", "API-BUSINESS-FLOW", "API-SSRF", "API-MISCONFIG",
        "API-INVENTORY", "API-UNSAFE-CONSUMPTION",
    }

    assert api_ids.issubset(by_id)
    assert all(by_id[code]["standard"] == "OWASP API Security Top 10:2023" for code in api_ids)
    assert all(by_id[code]["manual"].strip() for code in api_ids)
    assert "workflow" in by_id["API-BUSINESS-FLOW"]["manual"].lower()
    assert by_id["API-BUSINESS-FLOW"]["status"] == "not_run"

