from reports.coverage_evidence import build_coverage_evidence_dossiers


def test_dossiers_include_phase_diagnostics_findings_and_artifact_integrity():
    coverage = [{
        "id": "WSTG-INFO",
        "standard": "OWASP WSTG v4.2",
        "name": "Information Gathering",
        "phases": ["route_discovery", "information_disclosure"],
        "manual": "Review authenticated areas manually.",
    }]
    phases = [
        {"phase": "route_discovery", "status": "completed", "checks": 14, "duration_seconds": 2.4},
        {"phase": "information_disclosure", "status": "failed", "checks": 3, "error": "timeout"},
    ]
    findings = [{
        "id": "INFO-001",
        "title": "Information Gathering: exposed route",
        "category": "WSTG-INFO Information Gathering",
        "coverage_id": "WSTG-INFO",
        "severity": "Medium",
        "url": "https://example.test/diagnostics",
        "method": "GET",
        "evidence": "HTTP 200 exposed diagnostic content",
        "evidence_integrity_status": "verified_file",
        "evidence_integrity_artifacts": [{"relative_path": "evidence/diagnostics.png"}],
        "confidence": "High",
    }]
    [dossier] = build_coverage_evidence_dossiers(coverage, findings, phases)
    assert dossier["status"] == "partial_or_failed"
    assert dossier["phase_counts"] == {"total": 2, "completed": 1, "failed": 1, "not_run_or_skipped": 0}
    assert dossier["finding_counts"]["total"] == 1
    assert dossier["findings"][0]["artifacts"] == ["evidence/diagnostics.png"]
    assert dossier["findings"][0]["integrity_status"] == "verified_file"
    assert dossier["limitations"] == "Review authenticated areas manually."


def test_dossiers_never_claim_manual_only_area_was_tested():
    coverage = [{"id": "MANUAL-AUTH", "name": "Authenticated authorization review", "phases": [], "manual": "Requires test accounts."}]
    [dossier] = build_coverage_evidence_dossiers(coverage, [], [])
    assert dossier["status"] == "manual_review"
    assert dossier["phase_counts"]["total"] == 0
    assert dossier["finding_counts"]["total"] == 0
    assert "Requires test accounts." == dossier["limitations"]


def test_dossier_keeps_unexecuted_phase_as_not_run():
    coverage = [{"id": "API-01", "name": "API discovery", "phases": ["api_discovery"]}]
    [dossier] = build_coverage_evidence_dossiers(coverage, [], [{"phase": "api_discovery", "status": "not_run"}])
    assert dossier["status"] == "not_run"
    assert dossier["phases"][0]["status"] == "not_run"
