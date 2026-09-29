from scanners.authz_bola import _fingerprint, _safe_url

def test_safe_url_locks_to_origin():
    assert _safe_url("https://example.test", "/api/items/{id}", "123") == "https://example.test/api/items/123"

def test_safe_url_requires_path_template():
    try: _safe_url("https://example.test", "https://evil.test/items/{id}", "1")
    except ValueError: pass
    else: raise AssertionError("external template must be rejected")

def test_fingerprint_is_stable():
    class R: content=b"object"; status_code=200; headers={"Content-Type":"application/json"}
    assert _fingerprint(R()) == _fingerprint(R())

def test_fingerprint_changes_with_content():
    class R:
        status_code=200; headers={}
        def __init__(self, content): self.content=content
    assert _fingerprint(R(b"a"))["sha256"] != _fingerprint(R(b"b"))["sha256"]
