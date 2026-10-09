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
