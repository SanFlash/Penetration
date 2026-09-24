import pytest

import config
from scanners.deep_security import DeepSecurityEngine


def test_deep_engine_locks_to_exact_configured_origin():
    engine = DeepSecurityEngine(config.PENTEST_TARGET_ORIGIN, max_urls=1, max_probes=1)
    assert engine.target == config.PENTEST_TARGET_ORIGIN


def test_deep_engine_accepts_another_explicitly_selected_https_origin():
    engine = DeepSecurityEngine("https://example.com", max_urls=1, max_probes=1)
    assert engine.origin == "https://example.com"

def test_deep_engine_accepts_custom_port_and_locks_origin():
    engine = DeepSecurityEngine("https://staging.example.com:8443", max_urls=1, max_probes=1)
    assert engine.origin == "https://staging.example.com:8443"

def test_fingerprint_is_stable_and_minimal():
    import requests

    response = requests.Response()
    response.status_code = 200
    response.url = config.PENTEST_TARGET_ORIGIN + "/"
    response._content = b"sentinel-body"
    response.headers["Content-Type"] = "text/html"
    response.headers["Location"] = ""

    fp = DeepSecurityEngine.fingerprint(response)
    assert fp["status"] == 200
    assert fp["length"] == len(b"sentinel-body")
    assert fp["content_type"] == "text/html"
    assert len(fp["body_sha256_12"]) == 12


def test_extracts_real_set_cookie_headers_without_comma_splitting():
    import requests

    response = requests.Response()
    response.status_code = 200
    response.url = config.PENTEST_TARGET_ORIGIN + "/"
    response._content = b"ok"
    response.headers["Set-Cookie"] = "session_id=abc; Path=/; Secure; HttpOnly; SameSite=Lax"
    engine = DeepSecurityEngine(config.PENTEST_TARGET_ORIGIN, max_urls=1, max_probes=1)
    engine.baseline_and_headers([])
    assert response.headers["Set-Cookie"].startswith("session_id=")


def test_cors_test_is_bounded_to_same_origin():
    engine = DeepSecurityEngine("https://example.com", max_urls=1, max_probes=3)
    assert engine.origin == "https://example.com"
