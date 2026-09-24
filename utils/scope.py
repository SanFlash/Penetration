"""
utils/scope.py — the enforcement half of config.ALLOWED_HOSTS.

Every module that sends a network request imports assert_in_scope() and
calls it with the URL it is about to touch. There is no code path in this
framework that skips this check.
"""
from urllib.parse import urlparse
from config import ALLOWED_HOSTS


class OutOfScopeError(Exception):
    """Raised when a target host is not in config.ALLOWED_HOSTS."""


def host_of(url: str) -> str:
    parsed = urlparse(url)
    return parsed.netloc


def is_in_scope(url: str) -> bool:
    return host_of(url) in ALLOWED_HOSTS


def assert_same_target(target: str, url: str) -> None:
    """Fail closed unless URL belongs to the exact requested target origin."""
    target_parts = urlparse(target)
    url_parts = urlparse(url)
    if (target_parts.scheme.lower(), target_parts.netloc.lower()) != (url_parts.scheme.lower(), url_parts.netloc.lower()):
        raise OutOfScopeError(f"Refusing to assess '{url}'. Run is locked to '{target_parts.scheme}://{target_parts.netloc}' only.")


def assert_in_scope(url: str) -> None:
    if not is_in_scope(url):
        raise OutOfScopeError(
            f"Refusing to send a request to '{host_of(url)}' — it is not in "
            f"config.ALLOWED_HOSTS ({ALLOWED_HOSTS}). Add it there ONLY if "
            f"you own it or have written authorization to test it. See the "
            f"top of config.py before editing that list."
        )
