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

    assert data["schema_version"] == "2.0"
    assert data["total_findings"] == 1
    assert data["category_summary"]["Compatibility"] == 1
    assert data["metadata"]["profile"] == "compatibility"

    with open(result["html_path"], encoding="utf-8") as f:
        html = f.read()

    assert "Interactive Web Assessment" in html
    assert "Findings explorer" in html
    assert "Coverage" in html
