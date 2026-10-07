"""Focused information-disclosure checks for authorized web assessments."""
from __future__ import annotations

import re
from collections import Counter
from urllib.parse import urljoin, urlparse
import requests
from utils.scope import assert_same_target, OutOfScopeError

PATHS = (
    "/.env", "/.git/HEAD", "/.git/config", "/config.json", "/config.php",
    "/phpinfo.php", "/server-status", "/server-info", "/debug", "/debug/",
    "/actuator/env", "/swagger.json", "/openapi.json", "/api-docs",
    "/backup.zip", "/backup.tar.gz", "/db.sql", "/database.sql", "/dump.sql",
    "/composer.json", "/package.json", "/package-lock.json", "/.well-known/security.txt",
)
SECRET_RE = re.compile(r"(?i)(api[_-]?key|secret[_-]?key|access[_-]?token|password|passwd|private[_-]?key)\s*[:=]\s*['\"][^'\"]{8,}")
ERROR_MARKERS = ("traceback", "stack trace", "sqlstate", "sql syntax", "debug mode", "exception in thread", "fatal error")

class InformationDisclosureEngine:
    def __init__(self, target: str, max_probes: int = 80, timeout: int = 10):
        target = target.rstrip("/")
        p = urlparse(target)
        if p.scheme.lower() not in {"http","https"} or not p.netloc:
            raise ValueError("Target must be an absolute http:// or https:// URL.")
        self.target, self.origin = target, f"{p.scheme.lower()}://{p.netloc.lower()}"
        self.max_probes, self.timeout = max(1, min(int(max_probes), 120)), max(2, min(int(timeout), 30))
        self.session = requests.Session()
        self.session.headers.update({"User-Agent":"Sentinel-InfoDisclosure/1.0","Accept":"*/*"})
        self.findings, self.checks, self.probes = [], [], 0

    def same_origin(self, url):
        p,o=urlparse(url),urlparse(self.origin)
        return p.scheme.lower()==o.scheme.lower() and p.netloc.lower()==o.netloc.lower()

    def get(self,url):
        assert_same_target(self.target,url)
        if self.probes >= self.max_probes: raise RuntimeError("information-disclosure probe budget exhausted")
        self.probes += 1
        return self.session.get(url,timeout=self.timeout,allow_redirects=False,verify=True)

    def add(self,fid,title,severity,confidence,url,evidence,impact,fix):
        self.findings.append({"id":f"INFO-{fid}-{len(self.findings)+1:03d}","title":title,"severity":severity,
            "confidence":confidence,"category":"Information Disclosure","method":"GET","url":url,
            "evidence":evidence,"impact":impact,"remediation":fix})

    def run(self, urls=None):
        candidates=[self.target+p for p in PATHS]
        for raw in (urls or [])[:20]:
            if raw and self.same_origin(raw): candidates.append(raw)
        candidates=list(dict.fromkeys(candidates))[:self.max_probes]
        for url in candidates:
            try: r=self.get(url)
            except (requests.RequestException,OutOfScopeError) as exc:
                self.checks.append({"url":url,"error":f"{type(exc).__name__}: {exc}"}); continue
            body=r.text[:500000] if "text" in r.headers.get("Content-Type","").lower() or not r.headers.get("Content-Type") else ""
            self.checks.append({"url":url,"status":r.status_code,"content_type":r.headers.get("Content-Type",""),"bytes":len(r.content)})
            path=urlparse(url).path
            if r.status_code==200 and path in {"/.env","/.git/HEAD","/.git/config","/config.php","/config.json","/db.sql","/database.sql","/dump.sql"}:
                self.add("EXPOSED","Sensitive configuration/source-control/database resource is publicly accessible","High","High",url,
                         f"GET returned HTTP 200 for {path}; content length={len(r.content)} bytes.",
                         "Public configuration or database artifacts can expose credentials, source code or internal architecture.",
                         "Remove the artifact from the public deployment, deny access at the web/proxy layer, and rotate any real secrets.")
            if r.status_code==200 and path in {"/phpinfo.php","/server-status","/server-info","/debug","/debug/","/actuator/env"}:
                self.add("DIAGNOSTIC","Diagnostic or operational endpoint is publicly accessible","Medium","High",url,
                         f"GET returned HTTP 200 for {path}.",
                         "Diagnostic pages can reveal runtime, environment and infrastructure details.",
                         "Disable or protect diagnostic endpoints in production.")
            if r.status_code==200 and path in {"/swagger.json","/openapi.json","/api-docs"}:
                self.add("API-DOC","Public API documentation discovered","Low","High",url,
                         f"GET returned HTTP 200 for {path}.",
                         "Public API documentation expands an attacker's understanding of routes and parameters.",
                         "Make documentation private when it is not intentionally public and ensure every documented endpoint enforces authorization.")
            if r.status_code < 500 and body:
                if SECRET_RE.search(body):
                    self.add("SECRET","Secret-like assignment pattern detected in client-visible content","High","Medium",url,
                             "Response matched a secret/key/password heuristic; actual values are never stored in the report.",
                             "Client-visible credentials can be copied and abused against connected systems.",
                             "Remove secrets from client-delivered content and rotate any real credential.")
                hits=[m for m in ERROR_MARKERS if m in body.lower()]
                if hits:
                    self.add("ERROR","Verbose error/debug signature exposed","Medium","High",url,
                             f"Response contained controlled error markers: {', '.join(hits[:5])}.",
                             "Verbose errors can reveal framework, database and implementation details.",
                             "Return generic production errors and retain diagnostics only in server-side logs.")
            server=r.headers.get("Server",""); powered=r.headers.get("X-Powered-By","")
            if server or powered:
                self.add("HEADER","Technology fingerprint exposed by response headers","Low","High",url,
                         "; ".join(x for x in (f"Server={server}" if server else "",f"X-Powered-By={powered}" if powered else "") if x),
                         "Technology/version disclosure can help attackers select targeted attack paths.",
                         "Remove unnecessary server/framework version disclosure at the edge.")
        return {"findings":self.findings,"checks":self.checks,"probes":self.probes,
                "summary":{"probes":self.probes,"findings":len(self.findings),
                           "by_severity":dict(Counter(x["severity"] for x in self.findings))}}

def run_information_disclosure(target: str, urls=None, max_probes: int = 80):
    return InformationDisclosureEngine(target,max_probes=max_probes).run(urls)
