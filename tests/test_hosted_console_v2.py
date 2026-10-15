import pytest

import web


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("HTTPS://Example.COM:443/app/", "https://example.com/app"),
        ("http://Example.com:80/", "http://example.com"),
        ("https://example.com", "https://example.com"),
        ("https://[::1]:8443/app", "https://[::1]:8443/app"),
    ],
)
def test_validate_target_url_normalizes_origin_and_path(raw, expected):
    assert web._validate_target_url(raw) == expected


@pytest.mark.parametrize(
    "raw",
    [
        "",
        "example.com",
        "ftp://example.com",
        "https://",
        "https://user:secret@example.com",
        "https://example.com/path?token=secret",
        "https://example.com/#fragment",
        "https://example.com:99999",
        "https://example.com/\n/api",
    ],
)
def test_validate_target_url_rejects_ambiguous_or_unsafe_inputs(raw):
    with pytest.raises(ValueError):
        web._validate_target_url(raw)


def test_preflight_returns_profile_capabilities_without_starting_run(monkeypatch):
    monkeypatch.setattr(web, "ACCESS_TOKEN", "")
    client = web.app.test_client()
    response = client.get("/api/preflight?target=https%3A%2F%2Fexample.com&profile=pentest")
    assert response.status_code == 200
    payload = response.get_json()
    assert payload["valid"] is True
    assert payload["origin"] == "https://example.com"
    assert "deep_security" in payload["profile_capabilities"]["engines"]
    assert payload["authorization_required"] is True


def test_preflight_rejects_unknown_profile(monkeypatch):
    monkeypatch.setattr(web, "ACCESS_TOKEN", "")
    client = web.app.test_client()
    response = client.get("/api/preflight?target=https%3A%2F%2Fexample.com&profile=unknown")
    assert response.status_code == 400
    assert response.get_json()["error"] == "invalid_profile"


def test_run_rejects_embedded_credentials_before_worker_start(monkeypatch):
    monkeypatch.setattr(web, "ACCESS_TOKEN", "")
    client = web.app.test_client()
    response = client.post("/api/run", json={
        "target": "https://user:secret@example.com",
        "authorized": True,
        "profile": "pentest",
    })
    assert response.status_code == 400
    assert response.get_json()["error"] == "invalid_target"
