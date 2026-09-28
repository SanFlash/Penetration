import sys
import os
from urllib.parse import urlparse, parse_qsl

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scanners.input_stress import InputStressEngine, PAYLOADS


def test_stress_payloads_are_bounded():
    assert len(PAYLOADS) <= 12
    assert all(len(payload) <= 600 for _, payload in PAYLOADS)


def test_fuzz_url_replaces_only_selected_query_parameter():
    engine = InputStressEngine("https://example.test", max_urls=1, max_probes=1)
    url = "https://example.test/search?q=hello&page=2"
    mutated = engine.fuzz_url(url, "q", "STRESS_MARKER")
    assert dict(parse_qsl(urlparse(mutated).query)) == {
        "q": "STRESS_MARKER",
        "page": "2",
    }


def test_same_origin_rejects_other_host():
    engine = InputStressEngine("https://example.test", max_urls=1, max_probes=1)
    assert engine.same_origin("https://example.test/a") is True
    assert engine.same_origin("https://other.test/a") is False


if __name__ == "__main__":
    test_stress_payloads_are_bounded()
    test_fuzz_url_replaces_only_selected_query_parameter()
    test_same_origin_rejects_other_host()
    print("All input-stress tests passed.")
