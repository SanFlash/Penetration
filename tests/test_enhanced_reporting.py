import json
from pathlib import Path

from reports.report_generator import generate


def test_pentest_report_renders_coverage_and_evidence(tmp_path):
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    screenshot = evidence / "chromium_failure_mobile-small_home.png"
    screenshot.write_bytes(b"fake-png")

    result = generate(
        "https://amwebtech.com",
        [{
            "id": "COMP-PAGE-1",
            "title": "Page compatibility check failed",
            "severity": "Medium",
            "confidence": "High",
            "category": "Compatibility",
            "url": "https://amwebtech.com/",
            "evidence": "Timeout",
            "screenshot": str(screenshot),
        }],
        str(evidence),
        out_dir=str(tmp_path / "reports"),
        metadata={
            "profile": "pentest",
            "ui_responsive": {
                "urls_tested": ["https://amwebtech.com/"],
                "viewports": {"mobile-small": {"width": 375, "height": 812}},
                "results": [{
                    "browser": "chromium",
                    "viewport": "mobile-small",
                    "url": "https://amwebtech.com/",
                    "status": 500,
                    "load_ms": 123,
                    "console_errors": ["boom"],
                    "request_failures": [],
                    "horizontal_overflow": False,
                    "screenshot": str(screenshot),
                    "evidence_marked": True,
                }],
            },
            "security_evidence": [{
                "finding_id": "COMP-PAGE-1",
                "url": "https://amwebtech.com/",
                "status": 500,
                "screenshot": str(screenshot),
            }],
        },
    )

    data = json.loads(Path(result["json_path"]).read_text(encoding="utf-8"))
    assert data["schema_version"] == "3.0"
    assert data["browser_coverage"]["checks"] == 1
    assert data["browser_coverage"]["failures"] == 1
    assert data["browser_coverage"]["marked"] == 1
    assert data["evidence_gallery"]
    assert data["evidence_gallery"][0]["kind"] == "failure"

    report_html = Path(result["html_path"]).read_text(encoding="utf-8")
    assert "Visual evidence gallery" in report_html
    assert "Failure screenshots" in report_html
    assert "Chrome checks" in report_html
    assert "securityEvidence" in report_html
    assert "Open marked-up evidence" in report_html


def test_report_exposes_unrun_phases_in_explicit_coverage_matrix(tmp_path):
    result = generate(
        "https://example.com",
        [],
        str(tmp_path / "evidence"),
        out_dir=str(tmp_path / "reports"),
        metadata={
            "profile": "pentest",
            "phase_status": {
                "ui_responsive": {"status": "completed", "checks": 12},
                "functional_testing": {"status": "failed", "error": "browser closed"},
                "deep_security": {"status": "completed", "checks": 40},
            },
        },
    )

    data = json.loads(Path(result["json_path"]).read_text(encoding="utf-8"))
    matrix = {item["area"]: item for item in data["coverage_matrix"]}
    assert matrix["UI & Responsive"]["status"] == "completed"
    assert matrix["Functional"]["status"] == "failed_or_timed_out"
    assert matrix["Deep Security"]["status"] == "partial"
    assert matrix["Information Disclosure"]["status"] == "not_run"

    report_html = Path(result["html_path"]).read_text(encoding="utf-8")
    assert "Coverage matrix" in report_html
    assert "NOT RUN" in report_html
    assert "browser closed" in report_html


def test_report_includes_owasp_top10_engine_coverage_and_limitations(tmp_path):
    result = generate(
        "https://example.com",
        [],
        str(tmp_path / "evidence"),
        out_dir=str(tmp_path / "reports"),
        metadata={
            "profile": "pentest",
            "phase_status": {
                "security_headers": {"status": "completed"},
                "active_security": {"status": "completed"},
                "deep_security": {"status": "completed"},
                "input_validation": {"status": "timed_out"},
                "input_stress": {"status": "not_run"},
                "information_disclosure": {"status": "completed"},
                "api_surface": {"status": "completed"},
                "aggressive_readonly": {"status": "completed"},
                "functional_testing": {"status": "completed"},
            },
        },
    )
    data = json.loads(Path(result["json_path"]).read_text(encoding="utf-8"))
    owasp = {row["code"]: row for row in data["owasp_coverage"]}
    assert len(owasp) == 10
    assert owasp["A01:2021"]["status"] == "partial"
    assert owasp["A02:2021"]["status"] == "engines_completed"
    assert owasp["A03:2021"]["status"] == "partial"
    assert owasp["A09:2021"]["status"] == "not_run"
    assert "does not prove" in owasp["A01:2021"]["limitation"]

    html_report = Path(result["html_path"]).read_text(encoding="utf-8")
    assert "OWASP Top 10:2021" in html_report
    assert "OWASP Top 10:2025" in html_report
    assert "Mapped engines and limitations" in html_report
    assert "NOT RUN" in html_report

    current = {row["code"]: row for row in data["owasp_top10_2025_coverage"]}
    assert len(current) == 10
    assert current["A01:2025"]["status"] == "partial"
    assert current["A02:2025"]["status"] == "engines_completed"
    assert current["A03:2025"]["status"] == "manual_review"
    assert current["A09:2025"]["status"] == "manual_review"


def test_report_exposes_wstg_and_api_coverage_registry(tmp_path):
    result = generate(
        "https://example.com",
        [],
        str(tmp_path / "evidence"),
        out_dir=str(tmp_path / "reports"),
        metadata={"profile": "pentest", "phase_status": {
            "security_headers": {"status": "completed"},
            "active_security": {"status": "timed_out"},
        }},
    )
    data = json.loads(Path(result["json_path"]).read_text(encoding="utf-8"))
    coverage = {row["id"]: row for row in data["framework_coverage"]}
    assert len(coverage) >= 20
    assert coverage["WSTG-CONF"]["status"] == "partial_or_failed"
    assert coverage["LOGGING"]["status"] == "manual_review"
    html_report = Path(result["html_path"]).read_text(encoding="utf-8")
    assert "WSTG and API coverage registry" in html_report
    assert "API-BOLA" in html_report
    assert "Manual limitation:" in html_report


def test_report_generates_sarif_and_includes_it_in_bundle(tmp_path):
    result = generate(
        "https://example.com",
        [{
            "id": "SENTINEL-TEST-1",
            "title": "Missing security header",
            "description": "A recommended header was not observed.",
            "remediation": "Configure the response header.",
            "severity": "Medium",
            "category": "Security Headers",
            "url": "https://example.com/",
        }],
        str(tmp_path / "evidence"),
        out_dir=str(tmp_path / "reports"),
        metadata={"profile": "pentest"},
    )
    sarif_path = Path(result["sarif_path"])
    sarif = json.loads(sarif_path.read_text(encoding="utf-8"))
    assert sarif["version"] == "2.1.0"
    assert sarif["runs"][0]["results"][0]["level"] == "warning"
    assert result["report"]["exports"]["sarif_generated"] is True

    import zipfile
    with zipfile.ZipFile(result["report"]["exports"]["bundle_path"]) as bundle:
        names = set(bundle.namelist())
        assert "sentinel.sarif" in names
        assert "REPORT_BUNDLE_README.txt" in names
        assert "report.html" in names
        assert "findings.json" in names
        assert "evidence_manifest.json" in names
        assert bundle.testzip() is None
        assert result["report"]["exports"]["bundle_generated"] is True
        assert result["report"]["exports"]["bundle_size_bytes"] > 0


def test_report_integrates_verified_evidence_and_issue_linked_phase_logs(tmp_path):
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    screenshot = evidence / "diagnostic-endpoint.png"
    screenshot.write_bytes(bytes.fromhex(
        "89504e470d0a1a0a0000000d49484452000000010000000108060000001f15c489"
        "0000000d49444154789c6360606000000004000105f9d8"
        "0000000049454e44ae426082"
    ))

    result = generate(
        "https://example.test",
        [{
            "id": "DISC-1",
            "title": "Diagnostic endpoint exposed",
            "severity": "High",
            "category": "Information Disclosure",
            "url": "https://example.test/.well-known/diagnostic",
            "method": "GET",
            "evidence": "HTTP 200 with diagnostic banner",
            "remediation": "Remove the public diagnostic route.",
            "screenshot": str(screenshot),
        }],
        str(evidence),
        out_dir=str(tmp_path / "reports"),
        metadata={
            "profile": "pentest",
            "phase_status": {
                "information_disclosure": {
                    "status": "completed",
                    "checks": 4,
                    "findings": 1,
                    "duration_seconds": 1.25,
                    "summary": {"paths_checked": 4},
                }
            },
        },
    )

    report = json.loads(Path(result["json_path"]).read_text(encoding="utf-8"))
    finding = report["findings"][0]
    assert finding["evidence_integrity_status"] == "verified_file"
    assert finding["verified_screenshot_count"] == 1
    assert report["evidence_integrity_manifest"]["summary"]["findings_with_verified_screenshots"] == 1
    assert Path(result["report"]["exports"]["bundle_path"]).is_file()

    html_report = Path(result["html_path"]).read_text(encoding="utf-8")
    assert "Complete phase execution log" in html_report
    assert "information_disclosure" in html_report
    assert "DISC-1 · Diagnostic endpoint exposed" in html_report
    assert "integrity: verified_file" in html_report

    import zipfile
    with zipfile.ZipFile(result["report"]["exports"]["bundle_path"]) as bundle:
        names = set(bundle.namelist())
        assert "evidence_integrity.json" in names
        assert "evidence/diagnostic-endpoint.png" in names
        assert bundle.testzip() is None
