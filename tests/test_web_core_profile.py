import web
from ui.dashboard import DashboardState


def test_hosted_api_rejects_unknown_profile():
    client = web.app.test_client()
    response = client.post("/api/run", json={
        "target": "https://example.com",
        "authorized": True,
        "profile": "intrusive",
    })
    assert response.status_code == 400
    assert response.get_json()["error"] == "invalid_profile"


def test_hosted_api_passes_selected_core_profile_to_worker(monkeypatch):
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
            "target": "https://example.com",
            "authorized": True,
            "profile": "core",
        })
        assert response.status_code == 202
        assert response.get_json()["profile"] == "core"
        assert captured["args"] == ("https://example.com", "core")
        assert captured["started"] is True
    finally:
        if web._run_lock.locked():
            web._run_lock.release()


def test_status_exposes_core_report_paths_and_scope():
    previous = web._state
    try:
        web._state = DashboardState(target="https://example.com", profile="core")
        response = web.app.test_client().get("/api/status")
        assert response.status_code == 200
        data = response.get_json()
        assert data["reports"]["profile"] == "core"
        assert data["reports"]["html"] == "/reports/core_report.html"
        assert data["reports"]["findings_json"] == "/reports/core_report.json"
        assert data["reports"]["bundle"] == "/reports/sentinel_core_bundle.zip"
        assert data["coverage"]["ui_responsive"] == "not run"
    finally:
        web._state = previous
