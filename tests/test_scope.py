"""
tests/test_scope.py — proves the framework's core safety control actually
works: any host not in config.ALLOWED_HOSTS must be rejected.

Run with:  python3 -m pytest tests/ -v
       or:  python3 tests/test_scope.py
"""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.scope import is_in_scope, assert_in_scope, assert_same_target, OutOfScopeError


def test_allowed_host_passes():
    assert is_in_scope("http://127.0.0.1:5000/search?q=test") is True


def test_random_external_host_is_blocked():
    assert is_in_scope("https://example.com/anything") is False


def test_assert_in_scope_raises_for_out_of_scope_host():
    try:
        assert_in_scope("https://example.com/")
        raised = False
    except OutOfScopeError:
        raised = True
    assert raised, "assert_in_scope() must raise OutOfScopeError for an out-of-scope host"

def test_amwebtech_exact_target_lock():
    assert_same_target("https://amwebtech.com", "https://amwebtech.com/services/")

def test_exact_target_lock_rejects_other_allowed_host():
    try:
        assert_same_target("https://amwebtech.com", "http://127.0.0.1:5000/")
        raised = False
    except OutOfScopeError:
        raised = True
    assert raised, "exact target lock must reject other configured hosts"


def test_assert_in_scope_allows_configured_host():
    # Should not raise.
    assert_in_scope("http://127.0.0.1:5000/")


if __name__ == "__main__":
    tests = [
        test_allowed_host_passes,
        test_random_external_host_is_blocked,
        test_assert_in_scope_raises_for_out_of_scope_host,
        test_assert_in_scope_allows_configured_host,
        test_amwebtech_exact_target_lock,
        test_exact_target_lock_rejects_other_allowed_host,
    ]
    for t in tests:
        t()
        print(f"PASS: {t.__name__}")
    print("\nAll scope-enforcement tests passed.")
