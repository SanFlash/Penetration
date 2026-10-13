"""Fail-closed URL scope enforcement for Sentinel."""
from __future__ import annotations
import ipaddress
from urllib.parse import urlsplit
from config import ALLOWED_HOSTS


class OutOfScopeError(ValueError):
    """Raised when a request is not inside the explicitly configured scope."""


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
    host = p.hostname.rstrip(".").lower()
    try:
        host = ipaddress.ip_address(host).compressed
    except ValueError:
        try:
            host = host.encode("idna").decode("ascii")
        except UnicodeError as exc:
            raise OutOfScopeError("Invalid hostname.") from exc
    effective_port = port or (443 if scheme == "https" else 80)
    return scheme, host, effective_port, p


def canonical_origin(url: str) -> str:
    scheme, host, port, _ = _parts(url)
    default = 443 if scheme == "https" else 80
    display = f"[{host}]" if ":" in host else host
    return f"{scheme}://{display}" + (f":{port}" if port != default else "")


def host_of(url: str) -> str:
    scheme, host, port, _ = _parts(url)
    default = 443 if scheme == "https" else 80
    display = f"[{host}]" if ":" in host else host
    return display if port == default else f"{display}:{port}"


def is_in_scope(url: str) -> bool:
    try:
        scheme, host, port, _ = _parts(url)
        default = 443 if scheme == "https" else 80
        display = f"[{host}]" if ":" in host else host
        candidate = display if port == default else f"{display}:{port}"
        configured = {str(x).strip().lower().rstrip(".") for x in ALLOWED_HOSTS}
        return candidate in configured
    except OutOfScopeError:
        return False


def assert_same_target(target: str, url: str) -> None:
    expected, actual = canonical_origin(target), canonical_origin(url)
    if expected != actual:
        raise OutOfScopeError(f"Refusing to assess {url!r}: scan is locked to exact origin {expected!r}.")


def assert_in_scope(url: str) -> None:
    if not is_in_scope(url):
        raise OutOfScopeError(
            f"Refusing request to {url!r}; it is not an exact configured host in "
            "config.ALLOWED_HOSTS. Add a host only when you own it or have written authorization."
        )
