import requests
import pytest

from scanners.engine_core import (
    AssessmentEngine, AssessmentPolicy, BudgetExceeded, FindingRegistry,
    SafeTransport, redact,
)
from utils.scope import OutOfScopeError, assert_same_target, canonical_origin


def test_origin_canonicalization_and_default_ports():
    assert canonical_origin("https://EXAMPLE.com:443/path") == "https://example.com"
    assert canonical_origin("http://example.com:80") == "http://example.com"


@pytest.mark.parametrize("url", [
    "javascript:alert(1)", "file:///etc/passwd", "https://user:pass@example.com/",
    "https://example.com.evil.invalid/",
])
def test_rejects_malformed_or_unsafe_origins(url):
    with pytest.raises(OutOfScopeError):
        assert_same_target("https://example.com", url)


def test_target_lock_allows_same_origin_path_and_rejects_scheme_change():
    assert_same_target("https://example.com", "https://example.com/a?q=1")
    with pytest.raises(OutOfScopeError):
        assert_same_target("https://example.com", "http://example.com/a")


def test_policy_rejects_unbounded_or_mutating_defaults():
    with pytest.raises(ValueError):
        AssessmentPolicy("https://example.com", max_probes=100000)
    with pytest.raises(ValueError):
        AssessmentPolicy("https://example.com", methods=("GET", "POST"))


def test_finding_registry_ids_are_stable_and_deduplicate():
    registry = FindingRegistry()
    first = registry.add({"rule_id": "HDR-01", "url": "https://example.com/", "title": "Missing CSP"})
    second = registry.add({"rule_id": "HDR-01", "url": "https://example.com/", "title": "Missing CSP"})
    assert first["id"] == second["id"]
    assert len(registry.all()) == 1


def test_redaction_removes_secret_assignments():
    value = redact('password="not-a-real-password" api_key=abcd1234 Bearer abc.def.ghi')
    assert "not-a-real-password" not in value
    assert "abcd1234" not in value
    assert "abc.def.ghi" not in value
    extended = redact("AKIA1234567890ABCDEF eyJabcdefghijk.abcdefghijk.abcdefghijk")
    assert "AKIA1234567890ABCDEF" not in extended
    assert "eyJabcdefghijk.abcdefghijk.abcdefghijk" not in extended


def test_engine_distinguishes_completed_and_failed_checks():
    engine = AssessmentEngine(AssessmentPolicy("https://example.com", max_probes=3))
    engine.register("pass", lambda client: {"status": "completed", "checks": 4, "findings": []})
    engine.register("broken", lambda client: (_ for _ in ()).throw(RuntimeError("broken test")))
    report = engine.run()
    assert report["summary"]["overall_status"] == "partial"
    assert report["summary"]["completed_checks"] == 1
    assert report["summary"]["errored_checks"] == 1
    assert report["phase_status"][1]["errors"][0].startswith("RuntimeError")


def test_transport_blocks_methods_outside_policy_before_network():
    policy = AssessmentPolicy("https://example.com")
    transport = SafeTransport(policy, session=requests.Session())
    with pytest.raises(OutOfScopeError):
        transport.request("POST", "https://example.com/login")



def test_phase_call_preserves_partial_result_status():
    from main import _phase_call
    ledger = {}
    value = _phase_call("budgeted", ledger, lambda: {
        "assessment_status": "partial",
        "stop_reason": "phase budget reached",
        "findings": [],
    })
    assert value["assessment_status"] == "partial"
    assert ledger["budgeted"]["status"] == "partial"
    assert "phase budget reached" in ledger["budgeted"]["error"]



def test_assessment_status_is_partial_when_any_phase_is_partial():
    from main import _final_assessment_status
    assert _final_assessment_status({"headers": {"status": "completed"}}) == "COMPLETE"
    assert _final_assessment_status({
        "headers": {"status": "completed"},
        "input_validation": {"status": "partial"},
    }) == "PARTIAL"
    assert _final_assessment_status({"evidence": {"status": "timed_out"}}) == "PARTIAL"
