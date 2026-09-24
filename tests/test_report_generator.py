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
