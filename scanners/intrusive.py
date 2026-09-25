"""Controlled state-changing security tests with explicit rollback.

This module is intentionally configuration-driven. It will not discover arbitrary
write endpoints or submit production forms. Each operation must name a disposable
test resource and a rollback action.
"""
from __future__ import annotations

import json
import time
import uuid
from pathlib import Path
from urllib.parse import urljoin, urlparse

import requests

from utils.scope import assert_same_target, OutOfScopeError


SAFE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
MAX_ACTIONS = 12


class IntrusiveConfigurationError(ValueError):
    pass


def _same_origin(target: str, url: str) -> bool:
    try:
        assert_same_target(target, url)
        return True
    except OutOfScopeError:
        return False


def _resolve(target: str, value: str) -> str:
    if value.startswith("http://") or value.startswith("https://"):
        return value
    return urljoin(target.rstrip("/") + "/", value.lstrip("/"))


def _headers(spec: dict) -> dict:
    # Headers are intentionally supplied by the test configuration, not logged.
    return {str(k): str(v) for k, v in spec.get("headers", {}).items()}


def _json_body(spec: dict) -> dict | None:
    body = spec.get("json")
    return body if isinstance(body, dict) else None


def _request(session: requests.Session, method: str, url: str, spec: dict, timeout: int):
    return session.request(
        method=method,
        url=url,
        headers=_headers(spec),
        json=_json_body(spec),
        timeout=timeout,
        allow_redirects=False,
    )


def _extract_id(response: requests.Response, path: str | None) -> str | None:
    if not path:
        return None
    try:
        data = response.json()
    except ValueError:
        return None
    value = data
    for part in path.split("."):
        if isinstance(value, dict):
            value = value.get(part)
        else:
            return None
    return None if value is None else str(value)


def _render(value, resource_id: str | None = None, run_id: str = "") -> str:
    if not isinstance(value, str):
        return value
    return (
        value
        .replace("{resource_id}", resource_id or "")
        .replace("{run_id}", run_id)
    )


def _sanitize_response(response: requests.Response) -> dict:
    return {
        "status": response.status_code,
        "content_length": len(response.content),
        "content_type": response.headers.get("content-type", ""),
    }


def load_plan(path: str, target: str) -> list[dict]:
    plan_file = Path(path)
    if not plan_file.is_file():
        raise IntrusiveConfigurationError(
            f"Intrusive plan not found: {path}. "
            "Create it from intrusive_plan.example.json and configure a disposable test endpoint."
        )
    try:
        data = json.loads(plan_file.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise IntrusiveConfigurationError(
            f"Intrusive plan is not valid JSON: {path} ({exc.msg})."
        ) from exc
    if not isinstance(data, dict):
        raise IntrusiveConfigurationError("Intrusive plan must be a JSON object.")
    plan_target = data.get("target_origin")
    if plan_target and plan_target.rstrip("/") != target.rstrip("/"):
        raise IntrusiveConfigurationError(
            f"Plan target_origin must exactly match {target}."
        )
    operations = data.get("operations")
    if not isinstance(operations, list) or not operations:
        raise IntrusiveConfigurationError("Plan must contain a non-empty operations array.")
    if len(operations) > MAX_ACTIONS:
        raise IntrusiveConfigurationError(f"At most {MAX_ACTIONS} intrusive operations are allowed.")
    for index, op in enumerate(operations, 1):
        if not isinstance(op, dict):
            raise IntrusiveConfigurationError(f"Operation {index} is not an object.")
        method = str(op.get("method", "")).upper()
        rollback = op.get("rollback")
        if method not in SAFE_METHODS:
            raise IntrusiveConfigurationError(f"Operation {index}: unsupported method {method}.")
        if not isinstance(rollback, dict):
            raise IntrusiveConfigurationError(f"Operation {index}: rollback is required.")
        rollback_method = str(rollback.get("method", "")).upper()
        if rollback_method not in SAFE_METHODS:
            raise IntrusiveConfigurationError(f"Operation {index}: invalid rollback method.")
        url = _resolve(target, str(op.get("url", "")))
        rollback_url = _resolve(target, str(rollback.get("url", "")))
        if not _same_origin(target, url) or not _same_origin(target, rollback_url):
            raise IntrusiveConfigurationError(f"Operation {index}: exact-origin check failed.")
        if method in {"PUT", "PATCH"} and not op.get("restore_json"):
            raise IntrusiveConfigurationError(
                f"Operation {index}: PUT/PATCH requires restore_json for rollback."
            )
    return operations


def run_intrusive(target: str, plan_path: str, timeout: int = 10, dry_run: bool = False) -> dict:
    operations = load_plan(plan_path, target)
    session = requests.Session()
    session.headers.update({"User-Agent": "Sentinel-Intrusive/1.0 (authorized assessment)"})
    run_id = uuid.uuid4().hex[:12]
    records = []
    started = time.time()

    for index, op in enumerate(operations, 1):
        op_id = f"{run_id}-{index:02d}"
        method = str(op["method"]).upper()
        url = _resolve(target, _render(str(op["url"]), None, run_id))
        rollback = op["rollback"]
        rollback_method = str(rollback["method"]).upper()
        resource_id = None
        record = {
            "operation_id": op_id,
            "name": op.get("name", f"operation-{index}"),
            "method": method,
            "url": url,
            "rollback_method": rollback_method,
            "status": "DRY_RUN" if dry_run else "PENDING",
            "rollback_status": "NOT_RUN",
        }

        if dry_run:
            records.append(record)
            continue

        try:
            before = _request(session, "GET", url, {}, timeout)
            record["pre_state"] = _sanitize_response(before)

            action = _request(session, method, url, op, timeout)
            record["action"] = _sanitize_response(action)
            record["status"] = "ACTION_OK" if 200 <= action.status_code < 300 else "ACTION_FAILED"

            if record["status"] != "ACTION_OK":
                records.append(record)
                continue

            resource_id = _extract_id(action, op.get("id_path"))
            rollback_url = _render(_resolve(target, str(rollback["url"])), resource_id, run_id)
            rollback_spec = dict(rollback)
            if method in {"PUT", "PATCH"}:
                rollback_spec["json"] = op["restore_json"]

            if not _same_origin(target, rollback_url):
                raise IntrusiveConfigurationError("Rendered rollback URL left the exact target origin.")

            rb = _request(session, rollback_method, rollback_url, rollback_spec, timeout)
            record["rollback"] = _sanitize_response(rb)
            record["rollback_status"] = "OK" if 200 <= rb.status_code < 300 else "FAILED"
            record["resource_id"] = resource_id

            if record["rollback_status"] == "FAILED":
                record["status"] = "ROLLBACK_FAILED"
        except requests.RequestException as exc:
            record["status"] = "REQUEST_ERROR"
            record["error"] = str(exc)
        finally:
            records.append(record)

    failed_rollbacks = sum(1 for r in records if r["rollback_status"] == "FAILED")
    action_failures = sum(1 for r in records if r["status"] in {"ACTION_FAILED", "REQUEST_ERROR"})
    result = {
        "schema_version": "1.0",
        "run_id": run_id,
        "target": target,
        "dry_run": dry_run,
        "destructive_scope": "configured disposable resources only",
        "redirects": "disabled",
        "max_actions": MAX_ACTIONS,
        "operations": records,
        "summary": {
            "actions": len(records),
            "action_failures": action_failures,
            "rollbacks_ok": sum(1 for r in records if r["rollback_status"] == "OK"),
            "failed_rollbacks": failed_rollbacks,
            "runtime_seconds": round(time.time() - started, 2),
        },
    }
    Path("evidence").mkdir(exist_ok=True)
    Path("evidence/intrusive_security.json").write_text(
        json.dumps(result, indent=2), encoding="utf-8"
    )
    return result
