"""Shared scope-enforced HTTP transport with bounded, redacted evidence.

Security properties:
* exact allowlist checks before every request;
* redirects are never followed automatically;
* only callers that explicitly choose a method can send it;
* global thread-safe pacing and bounded timeouts;
* credentials and common secret values are redacted from evidence;
* evidence write failures are surfaced instead of silently losing audit data.
"""
from __future__ import annotations

import json
import os
import re
import threading
import time
from datetime import datetime, timezone
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import requests

from config import RATE_LIMIT_RPS, EVIDENCE_DIR
from utils.scope import assert_in_scope


class TargetConnectionError(RuntimeError):
    """Raised when an in-scope target cannot be reached."""

    def __init__(self, url: str, original: Exception):
        self.url = url
        self.original = original
        super().__init__(f"Target is unreachable: {url}. Check the authorized target and network.")


_LOCK = threading.Lock()
_last_request_time = 0.0
_SECRET_KEY = re.compile(r"(?:authorization|cookie|token|secret|password|passwd|api[_-]?key|session)", re.I)
_SECRET_VALUE = re.compile(
    r'(?i)(\b(?:password|passwd|secret|api[_-]?key|access[_-]?token)\b\s*[:=]\s*)'
    r'(["\'][^"\']*["\']|[^\s,;]+)'
)


def _redact_url(url: str) -> str:
    try:
        p = urlsplit(url)
        pairs = []
        for key, value in parse_qsl(p.query, keep_blank_values=True):
            pairs.append((key, "[REDACTED]" if _SECRET_KEY.search(key) else value))
        return urlunsplit((p.scheme, p.netloc, p.path, urlencode(pairs), ""))
    except Exception:
        return "[URL REDACTED]"


def _redact_text(value: str, limit: int = 2000) -> str:
    value = value or ""
    value = re.sub(
        r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----",
        "[REDACTED PRIVATE KEY]", value,
    )
    value = re.sub(r"\bAKIA[0-9A-Z]{16}\b", "[REDACTED AWS ACCESS KEY]", value)
    value = re.sub(
        r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b",
        "[REDACTED JWT]", value,
    )
    value = re.sub(r"(?im)^set-cookie\s*[:=].*$", "Set-Cookie: [REDACTED]", value)
    value = _SECRET_VALUE.sub(r'\1"[REDACTED]"', value)
    value = re.sub(r"(?i)(bearer\s+)[A-Za-z0-9._~+/-]+=*", r"\1[REDACTED]", value)
    return value[:limit]


def _throttle():
    global _last_request_time
    interval = 1.0 / max(float(RATE_LIMIT_RPS), 0.1)
    with _LOCK:
        now = time.monotonic()
        delay = interval - (now - _last_request_time)
        if delay > 0:
            time.sleep(delay)
        _last_request_time = time.monotonic()


def _log_evidence(method, url, resp, tag):
    os.makedirs(EVIDENCE_DIR, exist_ok=True)
    req = getattr(resp, "request", None)
    request_headers = {}
    if req is not None:
        request_headers = {
            k: ("[REDACTED]" if _SECRET_KEY.search(k) else v)
            for k, v in req.headers.items()
        }
    response_headers = {
        k: ("[REDACTED]" if _SECRET_KEY.search(k) else _redact_text(str(v), 500))
        for k, v in resp.headers.items()
    }
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "tag": str(tag)[:100],
        "method": method.upper(),
        "url": _redact_url(url),
        "status_code": resp.status_code,
        "request_headers": request_headers,
        "response_headers": response_headers,
        "response_body_snippet": _redact_text(getattr(resp, "text", "") or ""),
        "elapsed_ms": round(resp.elapsed.total_seconds() * 1000, 1) if getattr(resp, "elapsed", None) else None,
        "redirect_not_followed": bool(300 <= resp.status_code < 400 and resp.headers.get("Location")),
    }
    path = os.path.join(EVIDENCE_DIR, "raw_requests.jsonl")
    with open(path, "a", encoding="utf-8") as stream:
        stream.write(json.dumps(entry, ensure_ascii=False) + "\n")
    return entry


def _request(method, url, tag, **kwargs):
    assert_in_scope(url)
    # Do not permit a caller to silently re-enable cross-origin redirects.
    kwargs["allow_redirects"] = False
    kwargs.setdefault("timeout", (3.05, 10))
    kwargs.setdefault("verify", True)
    _throttle()
    try:
        response = requests.request(method.upper(), url, **kwargs)
    except requests.RequestException as exc:
        raise TargetConnectionError(url, exc) from exc
    _log_evidence(method, url, response, tag)
    return response


def get(url, tag="get", **kwargs):
    return _request("GET", url, tag, **kwargs)


def head(url, tag="head", **kwargs):
    return _request("HEAD", url, tag, **kwargs)


def options(url, tag="options", **kwargs):
    return _request("OPTIONS", url, tag, **kwargs)


def post(url, tag="post", **kwargs):
    # Kept for explicitly authorized, legacy lab workflows. Callers must still
    # pass scope enforcement and should prefer GET-only checks for production.
    return _request("POST", url, tag, **kwargs)
