"""Regression tests for finding IDs and non-repetitive report context."""

from reports.report_generator import _contextualize_findings


def test_repeated_findings_get_unique_ids_titles_and_descriptions():
    findings = [
        {
            "title": "Missing security response headers",
            "category": "Security",
            "url": f"https://example.test/page-{index}",
            "method": "GET",
            "severity": "Medium",
            "evidence": f"Missing header observation {index}",
        }
        for index in range(1, 16)
    ]

    result = _contextualize_findings(findings)

    assert len({item["id"] for item in result}) == len(result)
    assert len({item["title"] for item in result}) == len(result)
    assert len({item["description"] for item in result}) == len(result)
    assert all(item["issue_id"] == item["id"] for item in result)
    assert all(item["location_details"]["url"] for item in result)
    assert all(item["impact_assessment"]["severity"] == "Medium" for item in result)


def test_finding_context_uses_available_location_and_remediation():
    finding = {
        "title": "Potentially sensitive resource accessible",
        "category": "Information Disclosure",
        "url": "https://example.test/.well-known/diagnostic",
        "method": "GET",
        "parameter": "probe",
        "severity": "High",
        "evidence": "HTTP 200 with a diagnostic banner",
        "remediation": "Remove the diagnostic route from the public deployment.",
        "scanner": "disclosure",
        "status_code": 200,
    }

    result = _contextualize_findings([finding])[0]

    assert result["issue_id"].startswith("SNT-")
    assert "/.well-known/diagnostic" in result["description"]
    assert result["location_details"]["source_scanner"] == "disclosure"
    assert result["location_details"]["response_status"] == 200
    assert result["remediation"] == "Remove the diagnostic route from the public deployment."
