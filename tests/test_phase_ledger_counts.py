"""Phase ledger regression tests for complete execution reporting."""
import main


def test_phase_call_records_check_counts_findings_and_summary():
    ledger = {}
    result = main._phase_call(
        "input_validation",
        ledger,
        lambda: {
            "probes": 17,
            "findings": [{"id": "A"}, {"id": "B"}],
            "summary": {"candidate_points": 4, "invalid_cases": 2},
        },
    )

    assert result["probes"] == 17
    assert ledger["input_validation"]["status"] == "completed"
    assert ledger["input_validation"]["checks"] == 17
    assert ledger["input_validation"]["findings"] == 2
    assert ledger["input_validation"]["summary"]["invalid_cases"] == 2


def test_phase_call_records_check_list_length_when_probe_count_is_missing():
    ledger = {}
    main._phase_call(
        "functional_testing",
        ledger,
        lambda: {"checks": [{"url": "/a"}, {"url": "/b"}], "findings": []},
    )

    assert ledger["functional_testing"]["checks"] == 2
    assert ledger["functional_testing"]["findings"] == 0
