"""
utils/http_client.py — a thin wrapper around `requests` that every scanner
uses instead of calling requests.get/post directly. It enforces scope
(utils.scope.assert_in_scope) and a requests-per-second ceiling
(config.RATE_LIMIT_RPS) on every single call, and optionally logs the raw
request/response pair to config.EVIDENCE_DIR for later reporting.
"""
import json
import os
import time
from datetime import datetime, timezone

import requests

from config import RATE_LIMIT_RPS, EVIDENCE_DIR
from utils.scope import assert_in_scope

_last_request_time = 0.0
_min_interval = 1.0 / RATE_LIMIT_RPS


def _throttle():
    global _last_request_time
    elapsed = time.time() - _last_request_time
    if elapsed < _min_interval:
        time.sleep(_min_interval - elapsed)
    _last_request_time = time.time()


def _log_evidence(method, url, resp, tag):
    os.makedirs(EVIDENCE_DIR, exist_ok=True)
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "tag": tag,
        "method": method,
        "url": url,
        "status_code": resp.status_code,
        "response_headers": dict(resp.headers),
        "response_body_snippet": resp.text[:2000],
        "elapsed_ms": round(resp.elapsed.total_seconds() * 1000, 1),
    }
    path = os.path.join(EVIDENCE_DIR, "raw_requests.jsonl")
    with open(path, "a") as f:
        f.write(json.dumps(entry) + "\n")
    return entry


def get(url, tag="get", **kwargs):
    assert_in_scope(url)
    _throttle()
    resp = requests.get(url, timeout=10, **kwargs)
    _log_evidence("GET", url, resp, tag)
    return resp


def post(url, tag="post", **kwargs):
    assert_in_scope(url)
    _throttle()
    resp = requests.post(url, timeout=10, **kwargs)
    _log_evidence("POST", url, resp, tag)
    return resp
