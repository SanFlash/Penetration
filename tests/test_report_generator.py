import json

from reports.report_generator import generate


def test_interactive_report_contains_metadata_and_summaries(tmp_path):
    result = generate(
        "http://127.0.0.1:5000",
        [{
            "id": "T-1",
            "title": "Example",
            "severity": "Low",
            "confidence": "High",
            "category": "Compatibility",
            "url": "http://127.0.0.1:5000/",
            "evidence": "example",
        }],
        "evidence",
        out_dir=str(tmp_path),
        metadata={"profile": "compatibility"},
    )

    with open(result["json_path"], encoding="utf-8") as f:
        data = json.load(f)

    assert data["schema_version"] == "3.0"
    assert data["total_findings"] == 1
    assert data["category_summary"]["Compatibility"] == 1
    assert data["metadata"]["profile"] == "compatibility"

    with open(result["html_path"], encoding="utf-8") as f:
        html = f.read()

    assert "Interactive Web Assessment" in html
    assert "Findings explorer" in html
    assert "Coverage" in html

def test_security_observations_are_aggregated_but_raw_count_is_preserved(tmp_path):
    findings = [
        {
            "id": "DS-HEAD-001", "title": "Missing security response headers",
            "severity": "Low", "confidence": "High", "category": "Security Headers",
            "url": "https://example.com/", "evidence": "Missing: Content-Security-Policy, Referrer-Policy",
        },
        {
            "id": "DS-HEAD-002", "title": "Missing security response headers",
            "severity": "Low", "confidence": "High", "category": "Security Headers",
            "url": "https://example.com/about", "evidence": "Missing: Content-Security-Policy, Referrer-Policy",
        },
        {
            "id": "DS-SMAP-003", "title": "JavaScript source map publicly accessible",
            "severity": "Low", "confidence": "High", "category": "Information Disclosure",
            "url": "https://example.com/static/app.js.map", "evidence": "HTTP=200; content_length=1234",
        },
        {
            "id": "DS-SMAP-004", "title": "JavaScript source map publicly accessible",
            "severity": "Low", "confidence": "High", "category": "Information Disclosure",
            "url": "https://example.com/static/vendor.js.map", "evidence": "HTTP=200; content_length=5678",
        },
    ]
    result = generate("https://example.com", findings, "evidence", out_dir=str(tmp_path))

    assert result["report"]["raw_findings"] == 4
    assert result["report"]["unique_findings"] == 2
    assert result["report"]["total_observations"] == 4
    rows = result["report"]["findings"]
    assert any(x["title"] == "Missing security response headers" and x["observation_count"] == 2 for x in rows)
    assert any(x["title"] == "JavaScript source map publicly accessible" and x["observation_count"] == 2 for x in rows)
    assert all(len(x["affected_urls"]) >= 1 for x in rows)


def test_report_renders_correlated_attack_surface(tmp_path):
    metadata = {
        "profile": "pentest",
        "attack_surface": {
            "summary": {
                "total": 2,
                "api_like": 1,
                "documented": 1,
                "observed": 2,
                "state_changing_candidates": 1,
            },
            "routes": [{
                "method": "POST",
                "path": "/api/orders",
                "sources": ["javascript-axios", "openapi"],
                "api_like": True,
                "documented": True,
                "state_changing_candidate": True,
                "evidence": "axios.post('/api/orders')",
            }],
        },
    }
    result = generate("https://example.com", [], "evidence", out_dir=str(tmp_path), metadata=metadata)
    with open(result["html_path"], encoding="utf-8") as f:
        html = f.read()
    assert "Correlated attack surface" in html
    assert "/api/orders" in html
    assert "State-changing candidate" in html


def test_report_creates_portable_html_and_pdf_friendly_print_layout(tmp_path):
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    # Minimal valid PNG so the portable exporter can embed evidence.
    (evidence / "capture.png").write_bytes(
        bytes.fromhex(
            "89504e470d0a1a0a0000000d49484452000000010000000108060000001f15c489"
            "0000000d49444154789c6360606000000004000105f9d8"
            "0000000049454e44ae426082"
        )
    )
    result = generate(
        "http://127.0.0.1:5000",
        [],
        str(evidence),
        out_dir=str(tmp_path / "reports"),
        metadata={"profile": "pentest"},
    )

    assert result["portable_html_path"].endswith("report_portable.html")
    assert result["pdf_path"] is None or result["pdf_path"].endswith("report.pdf")
    portable = open(result["portable_html_path"], encoding="utf-8").read()
    assert "sentinel-report-mode" in portable
    assert "data:image/png;base64," in portable
    assert ".tab[hidden]{display:block!important" in open(result["html_path"], encoding="utf-8").read()


def test_xlsx_report_contains_failed_issue_and_embedded_evidence(tmp_path):
    from openpyxl import load_workbook
    from reports.xlsx_exporter import generate_xlsx, validate_xlsx

    evidence = tmp_path / "evidence"
    evidence.mkdir()
    screenshot = evidence / "failed-login.png"
    screenshot.write_bytes(
        bytes.fromhex(
            "89504e470d0a1a0a0000000d49484452000000010000000108060000001f15c489"
            "0000000d49444154789c6360606000000004000105f9d8"
            "0000000049454e44ae426082"
        )
    )
    report = {
        "target": "http://127.0.0.1:5000",
        "generated_at": "2026-09-30T12:00:00+00:00",
        "metadata": {"profile": "pentest"},
        "unique_findings": 1,
        "raw_findings": 1,
        "total_observations": 1,
        "severity_summary": {"Critical": 0, "High": 1, "Medium": 0, "Low": 0, "Info": 0},
        "evidence_gallery": [{"name": "failed-login.png", "kind": "failure", "size": screenshot.stat().st_size, "path": str(screenshot)}],
        "findings": [{
            "id": "P-001",
            "title": "Authorization failure",
            "severity": "High",
            "confidence": "High",
            "category": "Authorization",
            "method": "GET",
            "url": "http://127.0.0.1:5000/api/orders/2",
            "evidence": "Unauthorized account received protected object",
            "impact": "Protected data may be exposed.",
            "remediation": "Enforce object-level authorization.",
            "screenshots": [str(screenshot)],
            "screenshot": str(screenshot),
        }],
        "remediation": {"actions": []},
    }
    output = tmp_path / "penetration_report.xlsx"
    path = generate_xlsx(report, str(output))
    assert validate_xlsx(path)

    wb = load_workbook(path)
    try:
        assert "Failed Issues" in wb.sheetnames
        ws = wb["Failed Issues"]
        assert ws["A2"].value == "P-001"
        assert ws["B2"].value == "Authorization failure"
        assert ws["C2"].value == "High"
        assert len(ws._images) == 1
    finally:
        wb.close()


def test_finding_screenshot_uses_report_local_bundled_path(tmp_path):
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    screenshot = evidence / "security_001_failure.png"
    screenshot.write_bytes(
        bytes.fromhex(
            "89504e470d0a1a0a0000000d49484452000000010000000108060000001f15c489"
            "0000000d49444154789c6360606000000004000105f9d8"
            "0000000049454e44ae426082"
        )
    )
    result = generate(
        "http://127.0.0.1:5000",
        [{
            "id": "SEC-1",
            "title": "Focused browser failure",
            "severity": "Medium",
            "confidence": "High",
            "category": "Security",
            "url": "http://127.0.0.1:5000/login",
            "screenshot": str(screenshot),
            "evidence": "Visible error element captured.",
        }],
        str(evidence),
        out_dir=str(tmp_path / "reports"),
        metadata={"profile": "pentest"},
    )
    finding = result["report"]["findings"][0]
    assert finding["screenshots_relative"] == ["evidence/security_001_failure.png"]
    assert finding["screenshot_relative"] == "evidence/security_001_failure.png"
    assert (tmp_path / "reports" / "evidence" / "security_001_failure.png").is_file()
    assert "../" not in finding["screenshots_relative"][0]
