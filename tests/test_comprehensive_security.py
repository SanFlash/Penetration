from scanners.comprehensive_security import ComprehensiveSecurityEngine, COMMON_PATHS


def test_common_paths_are_bounded():
    assert len(COMMON_PATHS) <= 40


def test_engine_locks_to_supplied_origin():
    engine = ComprehensiveSecurityEngine("https://example.com", max_urls=2, max_probes=3)
    assert engine.origin == "https://example.com"
    assert all(engine.same_origin(url) for url in engine.seed_urls)


def test_out_of_origin_seed_is_ignored():
    engine = ComprehensiveSecurityEngine(
        "https://example.com",
        urls=["https://example.com/a", "https://evil.example/b"],
        max_urls=5,
        max_probes=3,
    )
    assert "https://evil.example/b" not in engine.seed_urls


def test_findings_are_deduplicated():
    engine = ComprehensiveSecurityEngine("https://example.com", max_urls=1, max_probes=1)
    engine._add(
        "X", "Example", "Low", "High", "Configuration",
        "https://example.com/", "evidence", "impact", "fix"
    )
    engine._add(
        "X", "Example", "Low", "High", "Configuration",
        "https://example.com/", "evidence", "impact", "fix"
    )
    assert len(engine.findings) == 1
