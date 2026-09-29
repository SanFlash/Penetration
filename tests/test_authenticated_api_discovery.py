from scanners.authenticated_api_discovery import _extract_candidates, _normalize, discover_authenticated


def test_normalize_rejects_external_target():
    try:
        _normalize("http://127.0.0.1:5000/", "https://example.com/api")
    except Exception:
        return
    raise AssertionError("external URL should be rejected")


def test_extract_candidates_finds_api_paths():
    values = _extract_candidates(
        '<script>fetch("/api/orders/1"); const x="/service/status";</script>',
        "http://127.0.0.1:5000/",
    )
    assert "http://127.0.0.1:5000/api/orders/1" in values
    assert "http://127.0.0.1:5000/service/status" in values


def test_discovery_limits_candidates():
    class FakeResponse:
        content = b'<a href="/one">one</a><script src="/app.js"></script>'
        text = content.decode()
        status_code = 200
        headers = {"Content-Type": "text/html"}

    class FakeSession:
        def get(self, url, **kwargs):
            return FakeResponse()

    result = discover_authenticated(
        FakeSession(), "http://127.0.0.1:5000", max_pages=2, max_candidates=1, max_runtime=5
    )
    assert result["pages_fetched"] <= 2
    assert len(result["candidates"]) <= 1


def test_discovery_never_submits_forms():
    html = '<form action="/delete" method="POST"><input name="id"></form>'
    values = _extract_candidates(html, "http://127.0.0.1:5000/")
    assert "http://127.0.0.1:5000/delete" not in values
