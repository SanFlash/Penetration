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
