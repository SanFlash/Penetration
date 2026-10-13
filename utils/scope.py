"""Fail-closed URL scope enforcement for Sentinel.

A scan is pinned to one exact origin. Host matching is canonicalized and never
uses substring/suffix matching. Redirects are handled as observations, not
followed automatically by the shared HTTP client.
"""
from __future__ import annotations

from urllib.parse import urlsplit
import ipaddress
import re

from config import ALLOWED_HOSTS


class OutOfScopeError(ValueError):
    """Raised when a request is not inside the explicitly configured scope."""


def _canonical_host(host: str) -> str:
    host = (host or "").rstrip(".").lower()
    if not host:
        raise OutOfScopeError("URL must contain a hostname.")
    try:
        return ipaddress.ip_address(host).compressed
    except ValueError:
        try:
            return host.encode("idna").decode("ascii")
        except UnicodeError as exc:
            raise OutOfScopeError("Invalid hostname.") from exc


def _parts(url: str):
    if not isinstance(url, str) or not url.strip():
        raise OutOfScopeError("URL must be a non-empty string.")
    try:
        p = urlsplit(url.strip())
        port = p.port
    except (ValueError, TypeError) as exc:
        raise OutOfScopeError(f"Malformed URL: {url!r}") from exc
    scheme = p.scheme.lower()
    if scheme not in {"http", "https"}:
        raise OutOfScopeError("Only http and https URLs are supported.")
    if not p.hostname or p.username is not None or p.password is not None:
        raise OutOfScopeError("URL must have a hostname and must not embed credentials.")
    host = _canonical_host(p.hostname)
    effective_port = port or (443 if scheme == "https" else 80)
    return scheme, host, effective_port, p


def canonical_origin(url: str) -> str:
    scheme, host, port, _ = _parts(url)
    default = 443 if scheme == "https" else 80
    host_display = f"[{host}]" if ":" in host else host
    return f"{scheme}://{host_display}" + (f":{port}" if port != default else "")


def host_of(url: str) -> str:
    scheme, host, port, _ = _parts(url)
    host_display = f"[{host}]" if ":" in host else host
    default = 443 if scheme == "https" else 80
    return host_display if port == default else f"{host_display}:{port}"


def is_in_scope(url: str) -> bool:
    try:
        _, host, port, _ = _parts(url)
        # ALLOWED_HOSTS entries are exact host[:port] values. A default port is
        # normalized away, matching the historical config format.
        display = f"[{host}]" if ":" in host else host
        default_http, default_https = port == 80, port == 443
        candidates = {display}
        if not (default_http or default_https):
            candidates.add(f"{display}:{port}")
        configured = {str(item).strip().lower().rstrip(".") for item in ALLOWED_HOSTS}
        return bool(candidates & configured)
    except OutOfScopeError:
        return False


def assert_same_target(target: str, url: str) -> None:
    expected = canonical_origin(target)
    actual = canonical_origin(url)
    if expected != actual:
        raise OutOfScopeError(
            f"Refusing to assess {url!r}: scan is locked to exact origin {expected!r}."
        )


def assert_in_scope(url: str) -> None:
    if not is_in_scope(url):
        raise OutOfScopeError(
            f"Refusing request to {url!r}; it is not an exact configured host in "
            f"config.ALLOWED_HOSTS. Add a host only when you own it or have written "
            f"authorization to assess it."
        )
