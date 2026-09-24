import pytest

import config
from scanners.deep_security import DeepSecurityEngine
from utils.scope import OutOfScopeError


def test_deep_engine_locks_to_exact_configured_origin():
    engine = DeepSecurityEngine(config.PENTEST_TARGET_ORIGIN, max_urls=1, max_probes=1)
    assert engine.target == config.PENTEST_TARGET_ORIGIN


def test_deep_engine_rejects_other_origin():
    with pytest.raises(OutOfScopeError):
        DeepSecurityEngine("https://www.amwebtech.com", max_urls=1, max_probes=1)


def test_deep_engine_rejects_non_allowlisted_host():
    with pytest.raises(OutOfScopeError):
        DeepSecurityEngine("https://example.com", max_urls=1, max_probes=1)


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
