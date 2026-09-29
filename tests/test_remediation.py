from reports.remediation import build_remediation_summary, enrich_finding


def test_enrich_finding_adds_actionable_remediation_fields():
    finding = {
        "title": "Wildcard CORS policy observed",
        "severity": "Low",
        "category": "CORS",
        "impact": "A public resource may be readable cross-origin.",
        "remediation": "Restrict CORS to trusted origins.",
    }
    result = enrich_finding(finding)
    assert result["fix_summary"] == finding["remediation"]
    assert result["validation_steps"]
    assert result["remediation_priority"] == "Backlog"


def test_build_remediation_summary_deduplicates_same_issue():
    findings = [
        {"title": "Missing security response headers", "severity": "Medium", "category": "Configuration", "url": "https://a.example", "impact": "impact", "remediation": "fix"},
        {"title": "Missing security response headers", "severity": "Medium", "category": "Configuration", "url": "https://b.example", "impact": "impact", "remediation": "fix"},
        {"title": "Verbose error disclosure", "severity": "High", "category": "Error Handling", "url": "https://a.example", "impact": "impact", "remediation": "fix"},
    ]
    summary = build_remediation_summary(findings)
    assert len(summary["actions"]) == 2
    assert summary["priority_counts"]["High"] == 1
    assert summary["priority_counts"]["Planned"] == 2
