"""Correlate passive route, API, form and crawler evidence into one inventory.

This module is inventory-only. It never sends requests or executes discovered
state-changing methods.
"""

from __future__ import annotations

from collections import Counter
from urllib.parse import urljoin, urlparse


def _add(items, seen, url, method, sources, state_changing=False, documented=False, api_like=False, evidence=None):
    if not url:
        return
    method = str(method or "GET").upper()
    key = (method, url)
    if key not in seen:
        seen.add(key)
        items.append({
            "url": url,
            "path": url,
            "method": method,
            "sources": sorted(set(sources)),
            "state_changing_candidate": bool(state_changing),
            "documented": bool(documented),
            "observed": False,
            "api_like": bool(api_like),
            "evidence": evidence,
        })
        return
    for item in items:
        if (item["method"], item["url"]) == key:
            item["sources"] = sorted(set(item["sources"]) | set(sources))
            item["state_changing_candidate"] |= bool(state_changing)
            item["documented"] |= bool(documented)
            item["api_like"] |= bool(api_like)
            if evidence and not item.get("evidence"):
                item["evidence"] = evidence
            break


def correlate_attack_surface(target: str, recon: dict | None = None,
                             route_discovery: dict | None = None,
                             api_surface: dict | None = None) -> dict:
    items = []
    seen = set()
    target = target.rstrip("/")

    recon = recon or {}
    route_discovery = route_discovery or {}
    api_surface = api_surface or {}

    for page in recon.get("pages", []) or []:
        url = page.get("url") if isinstance(page, dict) else page
        if url:
            _add(items, seen, str(url), "GET", ["crawler"])

    for form in recon.get("forms", []) or []:
        if not isinstance(form, dict):
            continue
        action = form.get("action") or form.get("url") or target + "/"
        method = form.get("method") or "GET"
        _add(items, seen, urljoin(target + "/", str(action)), method, ["form"],
             state_changing=str(method).upper() in {"POST", "PUT", "PATCH", "DELETE"},
             evidence="recon form")

    for route in route_discovery.get("routes", []) or []:
        if not isinstance(route, dict):
            continue
        _add(items, seen, route.get("url"), route.get("method"), [route.get("source", "route-discovery")],
             state_changing=route.get("state_changing"),
             api_like=route.get("api_like"),
             evidence=route.get("evidence"))

    for endpoint in api_surface.get("endpoints", []) or []:
        if not isinstance(endpoint, dict):
            continue
        path = str(endpoint.get("path") or "/")
        url = urljoin(target + "/", path.lstrip("/"))
        _add(items, seen, url, endpoint.get("method"), ["openapi"],
             state_changing=str(endpoint.get("method", "")).upper() in {"POST", "PUT", "PATCH", "DELETE"},
             documented=True, api_like=True,
             evidence=endpoint.get("operation_id") or endpoint.get("summary"))

    for item in items:
        item["path"] = urlparse(item["url"]).path or "/"
        item["observed"] = "crawler" in item["sources"] or any(
            source.startswith("javascript") or source in {"link", "form"} for source in item["sources"]
        )

    api_items = [x for x in items if x["api_like"]]
    state_items = [x for x in items if x["state_changing_candidate"]]
    documented_items = [x for x in items if x["documented"]]

    return {
        "schema": "attack-surface-1.0",
        "target": target,
        "policy": "inventory-only; discovered state-changing candidates are never executed",
        "summary": {
            "total": len(items),
            "api_like": len(api_items),
            "documented": len(documented_items),
            "observed": sum(1 for x in items if x["observed"]),
            "state_changing_candidates": len(state_items),
            "by_method": dict(Counter(x["method"] for x in items)),
            "by_source": dict(Counter(source for x in items for source in x["sources"])),
        },
        "routes": items[:1000],
    }
