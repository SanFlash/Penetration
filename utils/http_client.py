"""Central, scope-enforced HTTP client with throttling and evidence logging.

All scanner HTTP requests should use this module. It fails closed on scope,
uses bounded timeouts, and records a small reproducible request/response
summary for later reporting.
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


class TargetConnectionError(RuntimeError):
    """Raised when an in-scope target cannot be reached."""

    def __init__(self, url: str, original: Exception):
        self.url = url
        self.original = original
        super().__init__(
            f"Target is unreachable: {url}. "
            "Make sure the authorized target is running and the host/port is correct."
        )


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
        "request_headers": {
            k: v for k, v in resp.request.headers.items()
            if k.lower() not in {"authorization", "cookie"}
        },
        "response_headers": dict(resp.headers),
        "response_body_snippet": resp.text[:2000],
        "elapsed_ms": round(resp.elapsed.total_seconds() * 1000, 1),
    }
    path = os.path.join(EVIDENCE_DIR, "raw_requests.jsonl")
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    return entry


def _request(method, url, tag, **kwargs):
    assert_in_scope(url)
    _throttle()
    kwargs.setdefault("timeout", 10)
    try:
        resp = requests.request(method, url, **kwargs)
    except requests.RequestException as exc:
        raise TargetConnectionError(url, exc) from exc
    _log_evidence(method.upper(), url, resp, tag)
    return resp


def get(url, tag="get", **kwargs):
    return _request("GET", url, tag, **kwargs)


def post(url, tag="post", **kwargs):
    return _request("POST", url, tag, **kwargs)
