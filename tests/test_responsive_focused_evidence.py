from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "scanners" / "compatibility.py").read_text(encoding="utf-8")


def test_responsive_evidence_never_uses_full_page_screenshot():
    assert "full_page=True" not in SOURCE
    assert "page.screenshot(" not in SOURCE
    assert "locator.screenshot(" in SOURCE


def test_responsive_evidence_is_fail_only_and_element_scoped():
    assert '"passing_screenshots": False' in SOURCE
    assert '"failed_case_screenshots": True' in SOURCE
    assert '"capture_scope": "single-dom-element"' in SOURCE
    assert '"full_page_fallback": False' in SOURCE
    assert '"viewport_fallback": False' in SOURCE


def test_responsive_failures_have_specific_element_modes():
    assert '"overflow"' in SOURCE
    assert '"alt"' in SOURCE
    assert '"control"' in SOURCE
    assert '"error"' in SOURCE
    assert '"no-focused-region"' in SOURCE
