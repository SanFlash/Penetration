from scanners.active_security import _mutate_query


def test_mutate_query_preserves_other_parameters():
    mutated, parameter = _mutate_query(
        "https://amwebtech.com/search?q=hello&page=2",
        0,
        "SENTINEL",
    )
    assert parameter == "q"
    assert "q=SENTINEL" in mutated
    assert "page=2" in mutated


def test_mutate_query_changes_requested_index_only():
    mutated, parameter = _mutate_query(
        "https://amwebtech.com/search?q=hello&page=2",
        1,
        "'",
    )
    assert parameter == "page"
    assert "q=hello" in mutated
