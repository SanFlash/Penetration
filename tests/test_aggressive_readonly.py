from scanners.aggressive_readonly import AggressiveReadonlyEngine, PAYLOADS


def test_phase3_payloads_are_bounded():
    assert len(PAYLOADS) <= 11
    assert max(len(payload) for _, payload in PAYLOADS) <= 2048


def test_phase3_mutation_changes_only_selected_parameter():
    engine = AggressiveReadonlyEngine("https://example.test", max_urls=1, max_probes=1)
    url = "https://example.test/search?q=hello&page=2"
    mutated = engine.mutate_query(url, "q", "P3_MARKER")
    assert "q=P3_MARKER" in mutated
    assert "page=2" in mutated


def test_phase3_duplicate_parameter_is_same_origin():
    engine = AggressiveReadonlyEngine("https://example.test", max_urls=1, max_probes=1)
    url = engine.mutate_query("https://example.test/search?q=hello", "q", "P3_DUP", duplicate=True)
    assert engine.same_origin(url)
    assert "q=P3_DUP" in url
    assert "q=hello" in url


def test_phase3_rejects_other_origin():
    engine = AggressiveReadonlyEngine("https://example.test", max_urls=1, max_probes=1)
    assert engine.same_origin("https://example.test/a") is True
    assert engine.same_origin("https://evil.example/a") is False


def test_phase3_runtime_and_probe_caps_are_clamped():
    engine = AggressiveReadonlyEngine("https://example.test", max_urls=999, max_probes=999, max_runtime=9999)
    assert engine.max_urls == 120
    assert engine.max_probes == 1000
    assert engine.max_runtime == 600
