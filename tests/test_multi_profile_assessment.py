"""Tests for selectable hosted and focused assessment profiles."""
import pytest

import web
import main


@pytest.mark.parametrize("profile", [
    "pentest", "core", "security", "uiux", "functional", "input",
    "disclosure", "crawler", "api", "zap",
])
def test_hosted_api_accepts_each_supported_profile(monkeypatch, profile):
    captured = {}

    class FakeThread:
        def __init__(self, target, args, daemon):
            captured["args"] = args
            captured["target"] = target

        def start(self):
            captured["started"] = True

    monkeypatch.setattr(web.threading, "Thread", FakeThread)
    client = web.app.test_client()
    try:
        response = client.post("/api/run", json={
            "target": "https://example.test",
            "authorized": True,
            "profile": profile,
        })
        assert response.status_code == 202
        assert response.get_json()["profile"] == profile
        assert captured["args"] == ("https://example.test", profile)
        assert captured["started"] is True
    finally:
        if web._run_lock.locked():
            web._run_lock.release()


def test_hosted_api_rejects_unknown_profile(monkeypatch):
    client = web.app.test_client()
    response = client.post("/api/run", json={
        "target": "https://example.test",
        "authorized": True,
        "profile": "unbounded",
    })
    assert response.status_code == 400
    assert response.get_json()["error"] == "invalid_profile"


def test_focused_input_profile_records_validation_and_stress(monkeypatch):
    class FakeState:
        def __init__(self):
            self.events = []

        def update(self, **kwargs):
            self.events.append(kwargs)

    monkeypatch.setattr(main, "run_route_discovery", lambda *a, **k: {
        "completed": True, "probes": 3, "pages": ["https://example.test/"],
        "routes": [{"url": "https://example.test/search?q=x"}],
        "summary": {"pages": 2, "routes": 1},
    })
    monkeypatch.setattr(main, "run_input_validation", lambda *a, **k: {
        "probes": 4, "findings": [{"id": "VAL-1", "title": "Validation issue"}],
        "summary": {"findings": 1},
    })
    monkeypatch.setattr(main, "run_input_stress", lambda *a, **k: {
        "probes": 5, "findings": [], "summary": {"findings": 0},
    })
    captured = {}
    def fake_generate(*args, **kwargs):
        captured["findings"] = args[1]
        captured["metadata"] = kwargs["metadata"]
        return {"json_path": "findings.json", "html_path": "report.html", "report": {"total_findings": 1}}
    monkeypatch.setattr(main, "generate", fake_generate)
    state = FakeState()

    rc = main.run_focused_profile("https://example.test", "input", state_override=state)

    assert rc == 0
    assert any(event.get("stage") == "INPUT VALIDATION" for event in state.events)
    assert state.events[-1]["progress"] == 100
    assert captured["findings"][0]["id"] == "VAL-1"
    assert captured["metadata"]["profile"] == "input"
    assert captured["metadata"]["phase_status"]["input_validation"]["checks"] == 4
    assert captured["metadata"]["phase_status"]["input_stress"]["checks"] == 5


def test_zap_profile_without_configuration_is_reported_as_not_run(monkeypatch):
    from scanners import zap_baseline

    monkeypatch.delenv("SENTINEL_ZAP_API_URL", raising=False)
    monkeypatch.delenv("SENTINEL_ZAP_API_KEY", raising=False)
    monkeypatch.delenv("SENTINEL_ZAP_CONTEXT", raising=False)
    captured = {}
    monkeypatch.setattr(zap_baseline, "generate", lambda *a, **k: captured.update(kwargs=k.get("metadata", {})) or {})
    class FakeState:
        def __init__(self):
            self.events = []
        def update(self, **kwargs):
            self.events.append(kwargs)
    state = FakeState()

    rc = zap_baseline.run_zap_baseline("https://example.test", state=state)

    assert rc == 1
    assert captured["kwargs"]["status"] == "PARTIAL"
    assert captured["kwargs"]["phase_status"]["zap_baseline"]["status"] == "not_run"
    assert state.events[-1]["status"] == "PARTIAL"


def test_zap_baseline_records_complete_phase_ledger_without_active_scan(monkeypatch):
    from scanners import zap_baseline

    monkeypatch.setenv("SENTINEL_ZAP_API_URL", "http://zap:8080")
    monkeypatch.setenv("SENTINEL_ZAP_API_KEY", "test-key")
    monkeypatch.setenv("SENTINEL_ZAP_CONTEXT", "authorized-example")
    calls = []
    def fake_api_get(session, base, api_key, path, params=None, timeout=10):
        calls.append((path, params or {}))
        if path == "/JSON/core/view/version/":
            return {"version": "test"}
        if path == "/JSON/context/view/contextList/":
            return {"contextList": ["authorized-example"]}
        if path == "/JSON/context/view/includeRegexs/":
            return {"regexes": [r"https://example\.test.*"]}
        if path == "/JSON/spider/action/scan/":
            return {"scan": "1"}
        if path == "/JSON/spider/view/status/":
            return {"status": "100"}
        if path == "/JSON/pscan/view/recordsToScan/":
            return {"recordsToScan": "0"}
        if path == "/JSON/alert/view/alerts/":
            return {"alerts": [{
                "url": "https://example.test/", "pluginId": "10001",
                "alert": "Test passive alert", "risk": "Medium",
                "confidence": "High", "method": "GET",
                "description": "test description", "solution": "test fix",
            }]}
        raise AssertionError(f"Unexpected ZAP API path: {path}")

    captured = {}
    monkeypatch.setattr(zap_baseline, "_api_get", fake_api_get)
    monkeypatch.setattr(zap_baseline, "generate", lambda *a, **k: captured.update(metadata=k["metadata"], findings=a[1]) or {})
    monkeypatch.setattr(zap_baseline.time, "sleep", lambda _: None)

    class FakeState:
        def __init__(self):
            self.events = []
        def update(self, **kwargs):
            self.events.append(kwargs)

    state = FakeState()
    rc = zap_baseline.run_zap_baseline("https://example.test", state=state, max_runtime_seconds=30)

    assert rc == 0
    assert captured["metadata"]["status"] == "COMPLETE"
    assert captured["metadata"]["phase_status"]["zap_baseline"]["status"] == "completed"
    assert captured["metadata"]["phase_status"]["zap_spider"]["status"] == "completed"
    assert captured["metadata"]["phase_status"]["zap_passive"]["status"] == "completed"
    assert captured["findings"][0]["title"] == "Test passive alert"
    assert not any("/JSON/ascan/" in path for path, _ in calls)
