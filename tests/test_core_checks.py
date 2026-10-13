from collections import deque
from unittest.mock import Mock

from scanners.core_checks import check_cors_policy, check_query_inputs
from scanners.engine_core import AssessmentEngine, AssessmentPolicy, SafeTransport


class FakeResponse:
    def __init__(self, status=200, body="", headers=None):
        self.status_code = status
        self._content = body.encode()
        self.headers = headers or {"Content-Type": "text/html"}
        self.url = "https://example.com/"
        self.elapsed = None
        self.request = Mock(headers={})
    @property
    def text(self):
        return self._content.decode()


def test_cors_does_not_report_non_reflective_policy(monkeypatch):
    policy = AssessmentPolicy("https://example.com", max_probes=2)
    transport = SafeTransport(policy)
    monkeypatch.setattr(transport, "request", lambda *a, **kw: FakeResponse(headers={
        "Access-Control-Allow-Origin": "https://trusted.example",
        "Access-Control-Allow-Credentials": "true",
    }))
    class Engine:
        def __init__(self):
            self.policy = policy
            self.transport = transport
            self.checks = []
        def register(self, name, check):
            self.checks.append((name, check))
    engine = Engine()
    from scanners.core_checks import register_core_checks
    register_core_checks(engine)
    result = check_cors_policy(transport)
    assert result["findings"] == []


def test_cors_detects_reflected_origin_only_as_candidate(monkeypatch):
    policy = AssessmentPolicy("https://example.com", max_probes=2)
    transport = SafeTransport(policy)
    monkeypatch.setattr(transport, "request", lambda *a, **kw: FakeResponse(headers={
        "Access-Control-Allow-Origin": "https://sentinel-origin.invalid",
        "Access-Control-Allow-Credentials": "true",
    }))
    result = check_cors_policy(transport)
    assert result["findings"][0]["rule_id"] == "CORS-REFLECT-CREDENTIALS"
    assert result["findings"][0]["manual_validation_required"] is True


def test_query_input_check_is_skipped_without_query_pages():
    policy = AssessmentPolicy("https://example.com", max_probes=2)
    transport = SafeTransport(policy)
    transport._sentinel_pages = [{"url": "https://example.com/about", "response": FakeResponse()}]
    result = check_query_inputs(transport)
    assert result["checks"] == 0
    assert result["findings"] == []


def test_core_html_report_renders_css_and_escapes_findings(tmp_path):
    from sentinel_scan import _write_html
    destination = tmp_path / "report.html"
    _write_html({
        "target_origin": "https://example.com",
        "completed_at": "2026-10-13T00:00:00+00:00",
        "duration_seconds": 1.2,
        "request_count": 1,
        "checks_executed": 1,
        "findings": [{
            "severity": "High", "title": "<script>alert(1)</script>",
            "category": "Test", "url": "https://example.com/",
            "detail": "example", "remediation": "fix",
        }],
        "phase_status": [{"name": "headers", "status": "completed", "checks": 1,
                          "duration_ms": 2, "errors": []}],
        "summary": {"overall_status": "completed", "by_severity": {"high": 1, "critical": 0}},
        "limitations": ["Manual validation required"],
    }, destination)
    text = destination.read_text(encoding="utf-8")
    assert "grid-template-columns" in text
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in text
    assert "Manual validation required" in text



def test_evidence_key_is_stable_for_legacy_findings_without_ids():
    from scanners.browser_evidence import evidence_finding_key
    first = {"title": "Missing CSP", "url": "https://example.com/a"}
    same = {"title": "Missing CSP", "url": "https://example.com/a"}
    other = {"title": "Missing CSP", "url": "https://example.com/b"}
    assert evidence_finding_key(first) == evidence_finding_key(same)
    assert evidence_finding_key(first) != evidence_finding_key(other)
    assert evidence_finding_key({"rule_id": "CSP-01", **first}) == "CSP-01"
