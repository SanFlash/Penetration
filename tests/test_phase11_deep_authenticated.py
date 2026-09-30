import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scanners.phase11_deep_authenticated import (
    FUZZ_VALUES,
    build_url,
    classify_parameter,
)


def test_phase11_parameter_profiles_are_bounded():
    assert set(FUZZ_VALUES) >= {"text", "numeric", "identifier", "email", "boolean", "date"}
    assert all(len(value) <= 256 for values in FUZZ_VALUES.values() for value in values)


def test_phase11_parameter_classification():
    assert classify_parameter("email") == "email"
    assert classify_parameter("order_id") == "identifier"
    assert classify_parameter("page") == "numeric"
    assert classify_parameter("is_active") == "boolean"
    assert classify_parameter("start_date") == "date"
    assert classify_parameter("q") == "text"


def test_phase11_build_url_locks_to_origin():
    assert build_url("https://example.test", "/api/orders/{id}", object_id="42") == "https://example.test/api/orders/42"


def test_phase11_build_url_quotes_path_values():
    url = build_url("https://example.test", "/api/orders/{id}", object_id="../42")
    assert url == "https://example.test/api/orders/..%2F42"


def test_phase11_requires_absolute_endpoint():
    try:
        build_url("https://example.test", "api/orders/{id}", object_id="1")
    except ValueError:
        pass
    else:
        raise AssertionError("relative endpoint should be rejected")
