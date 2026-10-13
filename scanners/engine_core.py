"""Reusable, budgeted assessment primitives for Sentinel's scanner modules.

This is the execution core: one exact origin, finite request/runtime budgets,
redirects disabled, response-size limits, cancellation, deterministic findings,
per-check status accounting and redacted evidence. It intentionally does not
implement destructive actions, credential attacks or denial-of-service tests.
"""
from __future__ import annotations

import hashlib
import json
import re
import threading
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlsplit

import requests

from utils.scope import OutOfScopeError, assert_same_target, canonical_origin


@dataclass(frozen=True)
class AssessmentPolicy:
    target: str
    max_probes: int = 120
    max_runtime_seconds: int = 180
    rate_per_second: float = 2.0
    timeout_seconds: float = 8.0
    max_response_bytes: int = 1_500_000
    max_urls: int = 40
    methods: tuple[str, ...] = ("GET", "HEAD", "OPTIONS")

    def __post_init__(self):
        canonical_origin(self.target)
        if self.max_probes < 1 or self.max_probes > 2000:
            raise ValueError("max_probes must be between 1 and 2000")
        if self.max_runtime_seconds < 1 or self.max_runtime_seconds > 1800:
            raise ValueError("max_runtime_seconds must be between 1 and 1800")
        if self.max_urls < 1 or self.max_urls > 500:
            raise ValueError("max_urls must be between 1 and 500")
        if not 0.1 <= float(self.rate_per_second) <= 8:
            raise ValueError("rate_per_second must be between 0.1 and 8")
        if not 0.5 <= float(self.timeout_seconds) <= 30:
            raise ValueError("timeout_seconds must be between 0.5 and 30")
        if self.max_response_bytes < 1024 or self.max_response_bytes > 10_000_000:
            raise ValueError("max_response_bytes must be between 1024 and 10000000")
        normalized = tuple(str(m).upper() for m in self.methods)
        if any(m not in {"GET", "HEAD", "OPTIONS"} for m in normalized):
            raise ValueError("Only GET, HEAD and OPTIONS are allowed by the default policy")
        object.__setattr__(self, "methods", normalized)


class BudgetExceeded(RuntimeError):
    pass


class RunBudget:
    def __init__(self, policy: AssessmentPolicy):
        self.policy = policy
        self.started = time.monotonic()
        self._count = 0
        self._last = 0.0
        self._lock = threading.Lock()
        self.cancelled = threading.Event()

    @property
    def probes(self):
        with self._lock:
            return self._count

    def reserve(self):
        with self._lock:
            if self.cancelled.is_set():
                raise BudgetExceeded("assessment cancelled")
            if self._count >= self.policy.max_probes:
                raise BudgetExceeded("request budget exhausted")
            if time.monotonic() - self.started >= self.policy.max_runtime_seconds:
                raise BudgetExceeded("runtime budget exhausted")
            interval = 1.0 / self.policy.rate_per_second
            delay = interval - (time.monotonic() - self._last)
            if delay > 0:
                time.sleep(delay)
            self._last = time.monotonic()
            self._count += 1


_SECRET = re.compile(r"(?i)(authorization|cookie|token|secret|password|api[_-]?key)")
_ASSIGNMENT = re.compile(
    r'(?i)(\b(?:password|passwd|secret|api[_-]?key|access[_-]?token)\b\s*[:=]\s*)'
    r'(["\'][^"\']*["\']|[^\s,;]+)'
)


def redact(value: str, limit: int = 1500) -> str:
    text = value or ""
    text = re.sub(
        r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----",
        "[REDACTED PRIVATE KEY]", text,
    )
    text = re.sub(r"\bAKIA[0-9A-Z]{16}\b", "[REDACTED AWS ACCESS KEY]", text)
    text = re.sub(
        r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b",
        "[REDACTED JWT]", text,
    )
    text = re.sub(r"(?im)^set-cookie\s*[:=].*$", "Set-Cookie: [REDACTED]", text)
    text = _ASSIGNMENT.sub(r'\1"[REDACTED]"', text)
    text = re.sub(r"(?i)(bearer\s+)[A-Za-z0-9._~+/-]+=*", r"\1[REDACTED]", text)
    return text[:limit]


class SafeTransport:
    def __init__(self, policy: AssessmentPolicy, evidence_dir: str | Path | None = None,
                 session: requests.Session | None = None):
        self.policy = policy
        self.origin = canonical_origin(policy.target)
        self.budget = RunBudget(policy)
        self.session = session or requests.Session()
        self.session.headers.update({
            "User-Agent": "Sentinel-SecurityAssessment/3.0 (authorized testing)",
            "Accept": "text/html,application/json,application/xml,text/plain,*/*;q=0.8",
        })
        self.evidence_dir = Path(evidence_dir) if evidence_dir else None
        self.evidence: list[dict[str, Any]] = []

    def request(self, method: str, url: str, *, headers: dict[str, str] | None = None,
                params: dict[str, str] | None = None) -> requests.Response:
        method = method.upper()
        if method not in self.policy.methods:
            raise OutOfScopeError(f"Method {method} is not permitted by the active policy.")
        assert_same_target(self.policy.target, url)
        self.budget.reserve()
        response = self.session.request(
            method, url, headers=headers or {}, params=params,
            timeout=(min(3.05, self.policy.timeout_seconds), self.policy.timeout_seconds),
            allow_redirects=False, verify=True, stream=True,
        )
        body = bytearray()
        truncated = False
        try:
            for chunk in response.iter_content(chunk_size=65536):
                if not chunk:
                    continue
                remaining = self.policy.max_response_bytes - len(body)
                if remaining <= 0:
                    truncated = True
                    break
                body.extend(chunk[:remaining])
                if len(chunk) > remaining:
                    truncated = True
                    break
        finally:
            response.close()
        response._content = bytes(body)
        response._content_consumed = True
        response._sentinel_truncated = truncated
        self._record(method, url, response, bytes(body), truncated)
        return response

    def _record(self, method, url, response, body, truncated):
        parsed = urlsplit(url)
        safe_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        if parsed.query:
            safe_url += "?[query redacted]"
        entry = {
            "id": "EV-" + hashlib.sha256(
                f"{method}|{safe_url}|{response.status_code}|{hashlib.sha256(body).hexdigest()}".encode()
            ).hexdigest()[:12],
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "method": method,
            "url": safe_url,
            "status": response.status_code,
            "elapsed_ms": round(response.elapsed.total_seconds() * 1000, 1) if response.elapsed else None,
            "headers": {k: ("[REDACTED]" if _SECRET.search(k) else redact(str(v), 300))
                        for k, v in response.headers.items()},
            "body_sha256": hashlib.sha256(body).hexdigest(),
            "body_bytes_captured": len(body),
            "body_truncated": truncated,
            "body_snippet": redact(response.text, 1500),
            "redirect_not_followed": bool(300 <= response.status_code < 400 and response.headers.get("Location")),
        }
        self.evidence.append(entry)
        if self.evidence_dir:
            self.evidence_dir.mkdir(parents=True, exist_ok=True)
            with (self.evidence_dir / "engine_evidence.jsonl").open("a", encoding="utf-8") as stream:
                stream.write(json.dumps(entry, ensure_ascii=False) + "\n")


@dataclass
class CheckOutcome:
    name: str
    status: str
    checks: int = 0
    findings: list[dict[str, Any]] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    duration_ms: int = 0


class FindingRegistry:
    def __init__(self):
        self._items: dict[str, dict[str, Any]] = {}

    def add(self, finding: dict[str, Any]) -> dict[str, Any]:
        item = dict(finding)
        basis = "|".join(str(item.get(k, "")) for k in ("rule_id", "url", "parameter", "title"))
        item["id"] = item.get("id") or "SNT-" + hashlib.sha256(basis.encode()).hexdigest()[:12].upper()
        self._items.setdefault(item["id"], item)
        return self._items[item["id"]]

    def all(self) -> list[dict[str, Any]]:
        return sorted(self._items.values(), key=lambda f: (
            {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(
                str(f.get("severity", "info")).lower(), 5
            ), f["id"]
        ))


class AssessmentEngine:
    """Runs independent checks and preserves failure/skip status honestly."""
    def __init__(self, policy: AssessmentPolicy, transport: SafeTransport | None = None,
                 progress_callback: Callable[[dict[str, Any]], None] | None = None):
        self.policy = policy
        self.transport = transport or SafeTransport(policy)
        self.progress_callback = progress_callback
        self._checks: list[tuple[str, Callable[[SafeTransport], dict[str, Any]]]] = []
        self.registry = FindingRegistry()

    def _emit_progress(self, name: str, status: str, outcomes: list[CheckOutcome]) -> None:
        if not self.progress_callback:
            return
        try:
            self.progress_callback({
                "name": name,
                "status": status,
                "completed": len(outcomes),
                "total": len(self._checks),
                "request_count": self.transport.budget.probes,
                "finding_count": len(self.registry.all()),
            })
        except Exception:
            # Telemetry is best-effort and must never abort the assessment.
            pass

    def register(self, name: str, check: Callable[[SafeTransport], dict[str, Any]]) -> None:
        if not name.strip() or any(existing == name for existing, _ in self._checks):
            raise ValueError("Check names must be non-empty and unique.")
        self._checks.append((name, check))

    def run(self) -> dict[str, Any]:
        outcomes = []
        for name, check in self._checks:
            started = time.monotonic()
            try:
                raw = check(self.transport) or {}
                status = str(raw.get("status", "completed")).lower()
                if status not in {"completed", "partial", "skipped", "error"}:
                    status = "error"
                findings = raw.get("findings", []) or []
                for finding in findings:
                    self.registry.add(finding)
                errors = [str(x) for x in raw.get("errors", [])]
                if errors and status == "completed":
                    status = "partial"
                outcomes.append(CheckOutcome(
                    name=name, status=status, checks=max(0, int(raw.get("checks", 0))),
                    findings=[dict(f) for f in findings], errors=errors,
                    duration_ms=round((time.monotonic() - started) * 1000),
                ))
                self._emit_progress(name, status, outcomes)
            except BudgetExceeded as exc:
                outcomes.append(CheckOutcome(name, "partial", errors=[str(exc)],
                                             duration_ms=round((time.monotonic() - started) * 1000)))
                self._emit_progress(name, "partial", outcomes)
                # No further check can meaningfully run after the shared budget is exhausted.
                break
            except Exception as exc:
                outcomes.append(CheckOutcome(name, "error", errors=[f"{type(exc).__name__}: {exc}"],
                                             duration_ms=round((time.monotonic() - started) * 1000)))
                self._emit_progress(name, "error", outcomes)
        checks = sum(o.checks for o in outcomes)
        statuses = [o.status for o in outcomes]
        return {
            "schema_version": "3.0",
            "engine": "Sentinel Core",
            "author": "Satyendra Kumar Namdeo",
            "target_origin": self.transport.origin,
            "started_at": datetime.fromtimestamp(
                time.time() - (time.monotonic() - self.transport.budget.started), timezone.utc
            ).isoformat(),
            "completed_at": datetime.now(timezone.utc).isoformat(),
            "duration_seconds": round(time.monotonic() - self.transport.budget.started, 2),
            "request_count": self.transport.budget.probes,
            "request_budget": self.policy.max_probes,
            "checks_executed": checks,
            "phase_status": [asdict(o) for o in outcomes],
            "findings": self.registry.all(),
            "evidence": self.transport.evidence,
            "summary": {
                "finding_count": len(self.registry.all()),
                "by_severity": {
                    level: sum(str(f.get("severity", "")).lower() == level for f in self.registry.all())
                    for level in ("critical", "high", "medium", "low", "info")
                },
                "completed_checks": statuses.count("completed"),
                "partial_checks": statuses.count("partial"),
                "skipped_checks": statuses.count("skipped"),
                "errored_checks": statuses.count("error"),
                "overall_status": (
                    "error" if statuses and all(s == "error" for s in statuses) else
                    "partial" if any(s in {"partial", "error"} for s in statuses) else
                    "completed" if statuses else "no_checks"
                ),
            },
            "limitations": [
                "Automated findings are candidates, not proof of exploitability.",
                "No credentials, form submissions, uploads, destructive writes, brute force or denial-of-service tests are performed.",
                "Redirects are recorded but never followed automatically.",
                "Response bodies are capped and secret-like values are redacted in evidence.",
                "A missing finding does not establish that a vulnerability is absent.",
            ],
        }

    def write_json(self, report: dict[str, Any], path: str | Path) -> str:
        destination = Path(path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        temp = destination.with_suffix(destination.suffix + ".tmp")
        temp.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
        temp.replace(destination)
        return str(destination)
