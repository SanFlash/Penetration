"""Regression tests for finding-level context and evidence reporting."""
from reports.report_generator import _contextualize_findings


def test_repeated_issue_titles_get_unique_ids_titles_and_context():
    findings = [
        {
            "id": "DUPLICATE-ID",
            "title": "Missing security response headers",
            "category": "Security Headers",
            "severity": "Medium",
            "url": "https://example.test/account",
            "method": "GET",
            "evidence": "missing: Content-Security-Policy",
        },
        {
            "id": "DUPLICATE-ID",
            "title": "Missing security response headers",
            "category": "Security Headers",
            "severity": "Medium",
            "url": "https://example.test/checkout",
            "method": "GET",
            "parameter": "return_to",
            "evidence": "missing: X-Frame-Options",
        },
    ]

    result = _contextualize_findings(findings)

    assert len({item["issue_id"] for item in result}) == 2
    assert len({item["title"] for item in result}) == 2
    assert len({item["description"] for item in result}) == 2
    assert all(item["location_details"]["path"] for item in result)
    assert all(item["reproduction_steps"] for item in result)
    assert all(item["impact_assessment"]["validation_required"] for item in result)
    assert "Content-Security-Policy" in result[0]["description"]
    assert "X-Frame-Options" in result[1]["description"]


def test_missing_id_is_generated_and_context_does_not_claim_proof_of_exploitability():
    result = _contextualize_findings([{
        "title": "Potentially sensitive resource accessible",
        "category": "Information Disclosure",
        "severity": "High",
        "url": "https://example.test/.well-known/example",
        "evidence": "HTTP status=200",
    }])[0]

    assert result["id"].startswith("SNT-")
    assert result["issue_id"] == result["id"]
    assert "if confirmed" in result["impact"]
    assert "screenshot alone does not prove exploitability" in result["reproduction_steps"][-1]
