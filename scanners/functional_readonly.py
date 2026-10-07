"""Read-only functional smoke testing for authorized web assessments."""
from __future__ import annotations

from collections import Counter
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup

from utils.scope import assert_same_target, OutOfScopeError


class FunctionalReadonlyEngine:
    def __init__(self, target: str, max_urls: int = 60, max_links: int = 180, timeout: int = 10):
        target = target.rstrip("/")
        p = urlparse(target)
        if p.scheme.lower() not in {"http", "https"} or not p.netloc:
            raise ValueError("Target must be an absolute http:// or https:// URL.")
        self.target = target
        self.origin = f"{p.scheme.lower()}://{p.netloc.lower()}"
        self.max_urls = max(1, min(int(max_urls), 120))
        self.max_links = max(1, min(int(max_links), 500))
        self.timeout = max(2, min(int(timeout), 30))
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "Sentinel-FunctionalReadOnly/1.0", "Accept": "text/html,*/*"})
        self.findings, self.checks, self.probes = [], [], 0

    def same_origin(self, url: str) -> bool:
        p, o = urlparse(url), urlparse(self.origin)
        return p.scheme.lower() == o.scheme.lower() and p.netloc.lower() == o.netloc.lower()

    def get(self, url):
        assert_same_target(self.target, url)
        self.probes += 1
        return self.session.get(url, timeout=self.timeout, allow_redirects=False, verify=True)

    def add(self, fid, title, severity, confidence, url, evidence, impact, remediation):
        self.findings.append({
            "id": f"FUNC-{fid}-{len(self.findings)+1:03d}",
            "title": title, "severity": severity, "confidence": confidence,
            "category": "Functional Testing", "method": "GET", "url": url,
            "evidence": evidence, "impact": impact, "remediation": remediation,
        })

    def run(self, urls):
        selected = list(dict.fromkeys(u for u in urls if u and self.same_origin(u)))[:self.max_urls]
        links, seen = [], set()
        for url in selected:
            try:
                r = self.get(url)
            except (requests.RequestException, OutOfScopeError) as exc:
                self.checks.append({"url": url, "status": None, "error": f"{type(exc).__name__}: {exc}"})
                self.add("CONN", "Public route could not be reached", "Medium", "High", url, str(exc),
                         "Users may be unable to complete normal navigation.",
                         "Verify DNS, TLS, routing and application availability.")
                continue
            self.checks.append({"url": url, "status": r.status_code, "content_type": r.headers.get("Content-Type", "")})
            if r.status_code >= 500:
                self.add("5XX", "Public route returns a server error", "Medium", "High", url,
                         f"GET returned HTTP {r.status_code}.",
                         "A normal user journey can fail on this route.",
                         "Inspect server logs, handle expected exceptions and return controlled responses.")
            if "text/html" not in r.headers.get("Content-Type", "").lower():
                continue
            soup = BeautifulSoup(r.text[:750000], "html.parser")
            if not soup.title or not soup.title.get_text(" ", strip=True):
                self.add("TITLE", "Public page is missing a document title", "Low", "High", url,
                         "No meaningful <title> element was found.",
                         "Users and assistive technologies get less useful page context.",
                         "Add a meaningful unique title to every public route.")
            for form in soup.find_all("form"):
                method = (form.get("method") or "get").upper()
                action = (form.get("action") or "").strip()
                if not action:
                    self.add("FORM-ACTION", "Form has no explicit action", "Low", "Medium", url,
                             "A form relies on the browser's default action.",
                             "Form routing can change unexpectedly during refactors or deployment.",
                             "Declare the intended form action explicitly.")
                if method not in {"GET", "POST"}:
                    self.add("FORM-METHOD", "Form uses an unexpected HTTP method", "Low", "High", url,
                             f"Observed method={method}.",
                             "Unexpected methods can break browser/proxy handling.",
                             "Use a supported method and enforce authorization server-side.")
            for a in soup.find_all("a", href=True):
                href = a.get("href", "").strip()
                if not href or href.startswith(("#", "mailto:", "tel:", "javascript:")):
                    continue
                absolute = urljoin(url, href).split("#", 1)[0]
                if self.same_origin(absolute) and absolute not in seen:
                    seen.add(absolute); links.append(absolute)
                    if len(links) >= self.max_links:
                        break
        broken = 0
        for link in links[:self.max_links]:
            try:
                r = self.get(link)
            except (requests.RequestException, OutOfScopeError):
                continue
            if r.status_code >= 400:
                broken += 1
                self.add("LINK", "Internal navigation link returns an error",
                         "Medium" if r.status_code >= 500 else "Low", "High", link,
                         f"GET returned HTTP {r.status_code}.",
                         "Broken navigation can strand users and expose routing defects.",
                         "Repair/remove the link and add link-smoke checks to CI.")
        return {
            "findings": self.findings, "checks": self.checks, "probes": self.probes,
            "summary": {"urls_tested": len(selected), "navigation_links_checked": min(len(links), self.max_links),
                        "broken_links": broken, "findings": len(self.findings),
                        "by_severity": dict(Counter(x["severity"] for x in self.findings))}
        }


def run_functional_readonly(target: str, urls, max_urls: int = 60, max_links: int = 180):
    return FunctionalReadonlyEngine(target, max_urls=max_urls, max_links=max_links).run(urls)
