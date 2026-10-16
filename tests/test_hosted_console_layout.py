"""Regression tests for the redesigned hosted console and its truthful coverage UX."""
import re

import web


def test_console_has_responsive_navigation_and_all_coverage_panels():
    html = web._HTML
    assert 'href="#assessment"' in html
    assert 'href="#coverageReport"' in html
    assert 'href="#evidencePanel"' in html
    assert 'href="#executionLog"' in html
    assert 'id="coverageSections"' in html
    assert 'id="evidencePanel"' in html
    assert 'id="executionLog"' in html


def test_target_preview_is_explicitly_client_side_and_wired():
    html = web._HTML
    assert 'id="scopePreview"' in html
    assert "function updateScopePreview()" in html
    assert 'targetInput.addEventListener("input", updateScopePreview)' in html
    assert "Syntax preview only" in html
    assert "authorization and server-side scope are checked separately" in html


def test_start_handler_is_valid_async_and_error_path_reenables_button():
    script = re.search(r"<script[^>]*>([\s\S]*?)</script\s*>", web._HTML, re.IGNORECASE).group(1)
    assert "async function startRun() {" in script
    assert "async async function startRun()" not in script
    assert 'showState("ERROR", "START FAILED", message)' in script
    assert "setButton(false)" in script


def test_full_coverage_and_focused_profiles_remain_available():
    expected = {"pentest", "security", "uiux", "functional", "input", "api", "disclosure", "crawler", "zap", "core"}
    assert expected.issubset(set(web.ALLOWED_PROFILES))
    assert set(web.PROFILE_CAPABILITIES) >= expected
