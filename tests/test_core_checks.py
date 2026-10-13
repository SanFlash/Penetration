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
