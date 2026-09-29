"""Bounded authenticated API/route discovery.

Authentication is limited to one login request per configured account. After
login, discovery is GET-only, same-origin, redirect-free, and bounded by page,
candidate, and runtime limits. Credentials are never written to evidence.
"""
from __future__ import annotations

import hashlib
import os
import re
import time
from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse, urldefrag

import requests

from utils.scope import assert_same_target

DEFAULT_MAX_PAGES = 25
DEFAULT_MAX_CANDIDATES = 150
DEFAULT_TIMEOUT = 8
DEFAULT_MAX_RUNTIME = 90

_ENDPOINT_RE = re.compile(
    r"""(?:"|')((?:/|https?://)[A-Za-z0-9_./:{}?=&%+-]{2,220})(?:"|')"""
)
_API_RE = re.compile(r"/(?:api|ajax|rpc|graphql|service|endpoint)(?:/|$)", re.I)
_TEMPLATE_RE = re.compile(r"{[A-Za-z_][A-Za-z0-9_]*}|:[A-Za-z_][A-Za-z0-9_]*")


class _HTMLParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links: list[str] = []
        self.assets: list[str] = []
        self.inline_scripts: list[str] = []
        self._in_script = False

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag in {"a", "area", "link"} and attrs.get("href"):
            self.links.append(attrs["href"])
        if tag in {"script", "img", "iframe"} and attrs.get("src"):
            self.assets.append(attrs["src"])
        if tag == "script" and not attrs.get("src"):
            self._in_script = True

    def handle_data(self, data):
        if self._in_script:
            self.inline_scripts.append(data)

    def handle_endtag(self, tag):
        if tag == "script":
            self._in_script = False


def _normalize(base: str, value: str) -> str | None:
    if not value or value.startswith(("#", "mailto:", "tel:", "javascript:", "data:")):
        return None
    url, _ = urldefrag(urljoin(base, value.strip()))
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        return None
    assert_same_target(base, url)
    return url


def _extract_candidates(text: str, base: str) -> list[str]:
    found = []
    for raw in _ENDPOINT_RE.findall(text or ""):
        try:
            url = _normalize(base, raw)
        except Exception:
            continue
        if url:
            found.append(url)
    return found


def _fingerprint(response: requests.Response) -> dict:
    body = response.content[:200000]
    return {
        "status": response.status_code,
        "bytes": len(response.content),
        "content_type": response.headers.get("Content-Type", ""),
        "sha256": hashlib.sha256(body).hexdigest(),
    }


def login_with_env(base_url: str, user_env: str, pass_env: str, login_path: str) -> requests.Session:
    username, password = os.getenv(user_env), os.getenv(pass_env)
    if not username or not password:
        raise RuntimeError(f"Missing credentials in {user_env}/{pass_env}")
    if not login_path.startswith("/"):
        raise ValueError("login_path must begin with '/'")
    login_url = _normalize(base_url.rstrip("/") + "/", login_path)
    if not login_url:
        raise ValueError("Invalid login path")
    session = requests.Session()
    session.headers.update({"User-Agent": "Sentinel-Phase5-AuthDiscovery/1.0"})
    response = session.post(
        login_url,
        data={"username": username, "password": password},
        timeout=DEFAULT_TIMEOUT,
        allow_redirects=False,
    )
    if response.status_code not in {200, 201, 202, 204, 302, 303}:
        raise RuntimeError(f"Authentication failed: HTTP {response.status_code}")
    return session


def discover_authenticated(
    session: requests.Session,
    base_url: str,
    start_paths: list[str] | None = None,
    max_pages: int = DEFAULT_MAX_PAGES,
    max_candidates: int = DEFAULT_MAX_CANDIDATES,
    timeout: int = DEFAULT_TIMEOUT,
    max_runtime: int = DEFAULT_MAX_RUNTIME,
) -> dict:
    if max_pages < 1 or max_candidates < 1:
        raise ValueError("limits must be positive")
    started = time.monotonic()
    origin = base_url.rstrip("/") + "/"
    queue = [_normalize(origin, p) for p in (start_paths or ["/"])]
    queue = [u for u in queue if u]
    seen = set()
    candidates = {}
    observations = []

    while queue and len(seen) < max_pages and time.monotonic() - started < max_runtime:
        url = queue.pop(0)
        if url in seen:
            continue
        seen.add(url)
        response = session.get(url, timeout=timeout, allow_redirects=False)
        fp = _fingerprint(response)
        observations.append({"url": url, "fingerprint": fp})

        ctype = fp["content_type"].lower()
        if "text/html" in ctype:
            parser = _HTMLParser()
            parser.feed(response.text[:500000])
            values = parser.links + parser.assets
            for value in values:
                try:
                    normalized = _normalize(url, value)
                except Exception:
                    continue
                if normalized and normalized not in seen and len(queue) < max_pages * 2:
                    if urlparse(normalized).query == "" and normalized not in queue:
                        queue.append(normalized)

            # Only scan JavaScript for string-based API candidates. Do not scan
            # raw HTML attributes such as <form action="...">, which can cause
            # non-GET form targets to appear as API candidates.
            for script_text in parser.inline_scripts:
                for value in _extract_candidates(script_text, url):
                    if value not in candidates and len(candidates) < max_candidates:
                        candidates[value] = {
                            "url": value,
                            "source": url,
                            "kind": "api-like" if _API_RE.search(urlparse(value).path) else "endpoint",
                            "template": bool(_TEMPLATE_RE.search(value)),
                        }
        elif "javascript" in ctype or urlparse(url).path.endswith(".js"):
            for value in _extract_candidates(response.text, url):
                if value not in candidates and len(candidates) < max_candidates:
                    candidates[value] = {
                        "url": value,
                        "source": url,
                        "kind": "api-like" if _API_RE.search(urlparse(value).path) else "endpoint",
                        "template": bool(_TEMPLATE_RE.search(value)),
                    }

    return {
        "target": base_url,
        "authenticated": True,
        "limits": {
            "max_pages": max_pages,
            "max_candidates": max_candidates,
            "timeout": timeout,
            "max_runtime": max_runtime,
        },
        "pages_fetched": len(seen),
        "candidates": list(candidates.values()),
        "observations": observations,
        "notes": [
            "Discovery is GET-only after authentication.",
            "HTML links/assets are crawled; form actions are not treated as endpoint candidates.",
            "Inline/external JavaScript is parsed for string-based endpoint candidates.",
            "Credentials are not written to evidence.",
            "Candidate endpoints are inventory only; no candidate is invoked automatically.",
        ],
    }
