import json

from reports.sarif_exporter import build_sarif, write_sarif


def test_sarif_export_maps_severity_and_safe_locations(tmp_path):
    report = {
        "target": "https://example.com",
        "generated_at": "2026-10-09T00:00:00+00:00",
        "findings": [
            {
                "id": "SENTINEL-XSS-1",
                "title": "Potential reflected input",
                "description": "Input was reflected in the response.",
                "remediation": "Encode untrusted output.",
                "severity": "High",
                "category": "Injection",
                "confidence": "Medium",
                "url": "https://example.com/search?q=test",
            },
            {
                "id": "SENTINEL-LOCAL-2",
                "title": "Invalid location is ignored",
                "severity": "Info",
                "url": "file:///etc/passwd",
            },
        ],
    }

    sarif = build_sarif(report)
    assert sarif["version"] == "2.1.0"
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "Sentinel Web Security Assessment"
    assert len(run["results"]) == 2
    assert run["results"][0]["level"] == "error"
    assert run["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "https://example.com/search?q=test"
    assert "Recommended remediation" in run["results"][0]["message"]["text"]
    assert "locations" not in run["results"][1]
    assert run["properties"]["coverageIsExecutionOnly"] is True

    output = write_sarif(report, str(tmp_path / "reports" / "sentinel.sarif"))
    assert json.loads(open(output, encoding="utf-8").read()) == sarif
