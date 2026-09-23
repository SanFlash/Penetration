"""
recon/crawler.py — a safe, scope-limited crawler.

Discovers pages and links within a single authorized host and records every
<form> it finds (action, method, and input names) so scanners have concrete
endpoints and parameters to test, instead of guessing.

Refuses to leave the starting host (utils.scope.assert_in_scope raises if
it tries), and self-throttles via utils.http_client.
"""
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup

from utils.http_client import get, TargetConnectionError
from utils.scope import is_in_scope, host_of


class SafeCrawler:
    def __init__(self, start_url: str, max_pages: int = 25):
        self.start_url = start_url
        self.start_host = host_of(start_url)
        self.max_pages = max_pages
        self.visited = set()
        self.pages = []
        self.forms = []

    def crawl(self):
        queue = [self.start_url]
        while queue and len(self.visited) < self.max_pages:
            url = queue.pop(0)
            if url in self.visited or not is_in_scope(url):
                continue
            self.visited.add(url)

            try:
                resp = get(url, tag="crawl")
            except TargetConnectionError as exc:
                # One broken/stale internal URL must not abort the full assessment.
                # If the starting target itself is unreachable, fail fast.
                if url == self.start_url:
                    raise
                self.pages.append({
                    "url": url,
                    "status": None,
                    "error": str(exc),
                })
                continue
            self.pages.append({"url": url, "status": resp.status_code})

            if "text/html" not in resp.headers.get("Content-Type", ""):
                continue

            soup = BeautifulSoup(resp.text, "html.parser")

            for form in soup.find_all("form"):
                action = urljoin(url, form.get("action", url))
                if not is_in_scope(action):
                    continue
                inputs = [
                    inp.get("name")
                    for inp in form.find_all(["input", "textarea"])
                    if inp.get("name")
                ]
                self.forms.append({
                    "page": url,
                    "action": action,
                    "method": form.get("method", "GET").upper(),
                    "inputs": inputs,
                })

            for a in soup.find_all("a", href=True):
                next_url = urljoin(url, a["href"]).split("#", 1)[0]
                if is_in_scope(next_url) and next_url not in self.visited:
                    queue.append(next_url)

        return {"pages": self.pages, "forms": self.forms}
