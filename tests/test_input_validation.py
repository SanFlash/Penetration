import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scanners.input_validation import InputValidationEngine, classify_parameter, PROFILES


def test_parameter_classification():
    assert classify_parameter("email") == "email"
    assert classify_parameter("order_id") == "identifier"
    assert classify_parameter("page") == "numeric"
    assert classify_parameter("is_active") == "boolean"
    assert classify_parameter("start_date") == "date"
    assert classify_parameter("q") == "text"


def test_profiles_have_valid_and_invalid_cases():
    assert set(PROFILES) >= {"numeric", "email", "boolean", "date", "identifier", "text"}
    for profile in PROFILES.values():
        assert profile["valid"]
        assert len(profile["invalid"]) >= 3
        assert all(len(value) <= 2048 for value in profile["invalid"])


def test_mutate_preserves_other_parameters():
    engine = InputValidationEngine("https://example.test", max_urls=1, max_probes=1)
    mutated = engine.mutate("https://example.test/search?q=hello&page=2", "q", "bad value")
    assert "page=2" in mutated
    assert "q=bad+value" in mutated


def test_candidate_points_ignore_urls_without_query():
    engine = InputValidationEngine("https://example.test", max_urls=5, max_probes=1)
    assert engine.candidate_points(["https://example.test/home"]) == []
