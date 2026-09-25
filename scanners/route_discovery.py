"""Passive same-origin route and API-candidate discovery.

Only GET requests are made. Forms and JavaScript are parsed as evidence; their
state-changing methods are inventoried but never submitted.
"""

from __future__ import annotations

import json
import os
import re
import time
from collections import Counter
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup

import config

UA = "Sentinel-RouteDiscovery/1.0 (authorized security assessment)"
DEFAULT_TIMEOUT = getattr(config, "SECURITY_TIMEOUT", 10)
DEFAULT_RPS = max(float(getattr(config, "SECURITY_RATE_RPS", 2)), 0.2)
REQUEST_TIMEOUT = max(float(getattr(config, "ROUTE_DISCOVERY_TIMEOUT", 8)), 2.0)
MAX_RUNTIME = max(float(getattr(config, "ROUTE_DISCOVERY_MAX_RUNTIME", 120)), 15.0)

HTTP_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE"}
API_HINT = re.compile(r"(?:^|/)(?:api|api/v\d+|graphql|rest)(?:/|$)", re.I)
API_EXT = re.compile(r"\.(?:json|xml)$", re.I)

FETCH_RE = re.compile(
    r"""fetch\s*\(\s*['"]([^'"]+)['"](?:\s*,\s*\{.*?method\s*:\s*['"]([A-Za-z]+)['"].*?\})?""",
    re.I | re.S,
)
AXIOS_RE = re.compile(r"""axios\.(get|post|put|patch|delete|head)\s*\(\s*['"]([^'"]+)['"]""", re.I)
XHR_RE = re.compile(
    r"""\.open\s*\(\s*['"]([A-Za-z]+)['"]\s*,\s*['"]([^'"]+)['"]""", re.I
)
PATH_RE = re.compile(r"""['"]((?:/api(?:/[^'"]*)?|/graphql(?:/[^'"]*)?|/rest(?:/[^'"]*)?))['"]""", re.I)
GENERIC_ENDPOINT_RE = re.compile(r"""(?:fetch|axios\.(?:get|post|put|patch|delete|head)|\.(?:open|post|put|patch|delete|get))\s*\(\s*['"]([^'"]+)['"]""", re.I)
TEMPLATE_ENDPOINT_RE = re.compile(r"""(?:fetch|axios\.(?:get|post|put|patch|delete|head))\s*\(\s*\x60([^\x60]+)\x60""", re.I)


class RouteDiscoveryEngine:
    def __init__(self, target: str, max_pages: int = 8, max_assets: int = 20, max_candidates: int = 200):
        target = target.rstrip("/")
        parsed = urlparse(target)
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.netloc:
            raise ValueError("Target must be an absolute http:// or https:// URL.")
        self.target = target
        self.origin = f"{parsed.scheme.lower()}://{parsed.netloc.lower()}"
        self.max_pages = max(1, min(int(max_pages), 20))
        self.max_assets = max(1, min(int(max_assets), 50))
        self.max_candidates = max(1, min(int(max_candidates), 500))
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": UA, "Accept": "text/html,application/javascript,*/*;q=0.8"})
        self.last_request = 0.0
        self.probes = 0
        self.pages = []
        self.routes = []
        self.assets = []
        self.checks = []
        self._seen_routes = set()
        self.started = time.monotonic()

    def same_origin(self, url: str) -> bool:
        p, o = urlparse(url), urlparse(self.origin)
        return p.scheme.lower() == o.scheme.lower() and p.netloc.lower() == o.netloc.lower()

    def _get(self, url: str):
        if not self.same_origin(url):
            raise ValueError(f"Out-of-origin URL blocked: {url}")
        interval = 1.0 / DEFAULT_RPS
        delay = interval - (time.monotonic() - self.last_request)
        if delay > 0:
            time.sleep(delay)
        response = self.session.get(url, timeout=REQUEST_TIMEOUT, allow_redirects=False, verify=True)
        self.last_request = time.monotonic()
        self.probes += 1
        elapsed = time.monotonic() - self.started
        print(f"[DISCOVERY] GET {self.probes:02d} | {response.status_code} | {url} | {elapsed:.1f}s", flush=True)
        return response

    def _add_route(self, raw_url: str, method: str, source: str, discovered_from: str, evidence: str):
        if not raw_url or len(self.routes) >= self.max_candidates:
            return
        url = urljoin(discovered_from, raw_url)
        if not self.same_origin(url):
            return
        parsed = urlparse(url)
        clean = parsed._replace(fragment="").geturl()
        method = (method or "GET").upper()
        if method not in HTTP_METHODS:
            method = "GET"
        key = (method, clean)
        if key in self._seen_routes:
            return
        self._seen_routes.add(key)
        path = parsed.path or "/"
        self.routes.append({
            "url": clean,
            "path": path,
            "method": method,
            "state_changing": method in {"POST", "PUT", "PATCH", "DELETE"},
            "source": source,
            "discovered_from": discovered_from,
            "evidence": evidence[:500],
            "api_like": bool(
                API_HINT.search(path)
                or API_EXT.search(path)
                or any(token in path.lower() for token in ("/ajax/", "/rpc/", "/endpoint/", "/service/"))
            ),
        })

    def _parse_html(self, url: str, text: str):
        soup = BeautifulSoup(text[:500000], "html.parser")
        for tag in soup.find_all("a", href=True):
            self._add_route(tag["href"], "GET", "link", url, "HTML anchor")
        for tag in soup.find_all("form"):
            action = tag.get("action") or url
            method = tag.get("method", "GET")
            self._add_route(action, method, "form", url, f"form method={method.upper()}")
        for tag in soup.find_all("script", src=True):
            asset = urljoin(url, tag["src"])
            if self.same_origin(asset) and asset not in self.assets and len(self.assets) < self.max_assets:
                self.assets.append(asset)

        self._parse_script_text(url, text)

    def _parse_script_text(self, url: str, text: str):
        for match in FETCH_RE.finditer(text[:1000000]):
            self._add_route(match.group(1), match.group(2) or "GET", "javascript-fetch", url, match.group(0))
        for match in AXIOS_RE.finditer(text[:1000000]):
            self._add_route(match.group(2), match.group(1), "javascript-axios", url, match.group(0))
        for match in XHR_RE.finditer(text[:1000000]):
            self._add_route(match.group(2), match.group(1), "javascript-xhr", url, match.group(0))
        source_text = text[:1000000]
        for match in PATH_RE.finditer(source_text):
            self._add_route(match.group(1), "GET", "javascript-path", url, match.group(0))
        for match in GENERIC_ENDPOINT_RE.finditer(source_text):
            raw = match.group(1)
            if raw.startswith(("/", "http://", "https://")):
                self._add_route(raw, "GET", "javascript-endpoint", url, match.group(0))
        for match in TEMPLATE_ENDPOINT_RE.finditer(source_text):
            raw = match.group(1)
            if raw.startswith("/"):
                self._add_route(raw, "GET", "javascript-template", url, match.group(0))

    def run(self):
        started = time.time()
        self.started = time.monotonic()
        print(f"[DISCOVERY] Starting passive route discovery (max {self.max_pages} pages, {self.max_assets} JS assets, {MAX_RUNTIME:.0f}s budget)", flush=True)
        queue = [self.target + "/"]
        seen_pages = set()

        while queue and len(self.pages) < self.max_pages and (time.monotonic() - self.started) < MAX_RUNTIME:
            url = queue.pop(0)
            if url in seen_pages or not self.same_origin(url):
                continue
            seen_pages.add(url)
            try:
                response = self._get(url)
            except (requests.RequestException, ValueError):
                continue
            self.checks.append({
                "check": "page",
                "url": url,
                "status": response.status_code,
                "content_type": response.headers.get("Content-Type", ""),
                "length": len(response.content),
            })
            if response.status_code >= 400:
                continue
            self.pages.append(url)
            content_type = response.headers.get("Content-Type", "").lower()
            if "html" not in content_type:
                continue
            self._parse_html(url, response.text)

            soup = BeautifulSoup(response.text[:500000], "html.parser")
            for tag in soup.find_all("a", href=True):
                link = urljoin(url, tag["href"]).split("#", 1)[0]
                if self.same_origin(link) and link not in seen_pages and len(queue) < self.max_pages * 4:
                    queue.append(link)

        for index, asset in enumerate(self.assets, 1):
            if self.probes >= self.max_pages + self.max_assets or (time.monotonic() - self.started) >= MAX_RUNTIME:
                print("[DISCOVERY] Time/request budget reached; stopping JS asset inspection.", flush=True)
                break
            try:
                response = self._get(asset)
            except (requests.RequestException, ValueError):
                continue
            print(f"[DISCOVERY] JS asset {index}/{len(self.assets)} | {asset}", flush=True)
            self.checks.append({
                "check": "javascript-asset",
                "url": asset,
                "status": response.status_code,
                "content_type": response.headers.get("Content-Type", ""),
                "length": len(response.content),
            })
            content_type = response.headers.get("Content-Type", "").lower()
            asset_path = urlparse(asset).path.lower()
            if response.status_code < 400 and (
                "javascript" in content_type or asset_path.endswith((".js", ".mjs", ".cjs"))
            ):
                self._parse_script_text(asset, response.text)

        api_routes = [r for r in self.routes if r["api_like"]]
        state_changing = [r for r in self.routes if r["state_changing"]]
        result = {
            "schema": "route-discovery-1.0",
            "target": self.target,
            "scope_lock": self.origin,
            "scope_policy": "exact target origin; redirects disabled; GET-only network activity",
            "limits": {
                "max_pages": self.max_pages,
                "max_assets": self.max_assets,
                "max_candidates": self.max_candidates,
                "rate_rps": DEFAULT_RPS,
                "timeout_seconds": REQUEST_TIMEOUT,
                "max_runtime_seconds": MAX_RUNTIME,
            },
            "probes": self.probes,
            "pages": self.pages,
            "assets": self.assets,
            "routes": self.routes,
            "summary": {
                "pages": len(self.pages),
                "assets": len(self.assets),
                "routes": len(self.routes),
                "api_like_routes": len(api_routes),
                "state_changing_candidates": len(state_changing),
                "by_method": dict(Counter(r["method"] for r in self.routes)),
                "by_source": dict(Counter(r["source"] for r in self.routes)),
            },
            "checks": self.checks,
            "runtime_seconds": round(time.time() - started, 2),
            "completed": (time.monotonic() - self.started) < MAX_RUNTIME and not queue,
            "stop_reason": "time_budget" if (time.monotonic() - self.started) >= MAX_RUNTIME else "completed",
        }
        os.makedirs(config.EVIDENCE_DIR, exist_ok=True)
        with open(os.path.join(config.EVIDENCE_DIR, "discovered_routes.json"), "w", encoding="utf-8") as handle:
            json.dump(result, handle, indent=2, ensure_ascii=False)
        return result


def run_route_discovery(target: str, max_pages: int = 8, max_assets: int = 20, max_candidates: int = 200):
    return RouteDiscoveryEngine(target, max_pages=max_pages, max_assets=max_assets, max_candidates=max_candidates).run()
