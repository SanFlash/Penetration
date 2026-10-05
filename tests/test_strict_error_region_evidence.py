from scanners.browser_evidence import _focused_screenshot


class FakeLocator:
    def __init__(self, calls):
        self.calls = calls
        self.first = self

    def wait_for(self, **kwargs):
        self.calls.append(("wait_for", kwargs))

    def screenshot(self, **kwargs):
        self.calls.append(("screenshot", kwargs))
        # A tiny valid PNG is enough to exercise the capture path in isolation.
        from pathlib import Path
        Path(kwargs["path"]).write_bytes(
            bytes.fromhex(
                "89504e470d0a1a0a0000000d49484452000000010000000108060000001f15c489"
                "0000000d49444154789c6360606000000004000105f9d8"
                "0000000049454e44ae426082"
            )
        )


class FakePage:
    def __init__(self):
        self.calls = []
        self.locator_calls = []

    def locator(self, selector):
        self.locator_calls.append(selector)
        return FakeLocator(self.calls)


def test_no_focus_never_captures_viewport(tmp_path):
    page = FakePage()
    result = _focused_screenshot(page, str(tmp_path / "unused.png"), None)

    assert result["mode"] == "no-focused-region"
    assert result["focus_found"] is False
    assert page.locator_calls == []
    assert page.calls == []


def test_focus_captures_only_exact_error_element(tmp_path):
    page = FakePage()
    path = tmp_path / "evidence.png"
    focus = {
        "tag": "div",
        "id": "error",
        "className": "error-message",
        "text": "Access denied",
        "hits": ["access", "denied"],
        "errorWords": 1,
        "finding_id": "P-001",
    }

    result = _focused_screenshot(page, str(path), focus)

    assert result["mode"] == "exact-error-element"
    assert result["capture_scope"] == "single-dom-element"
    assert page.locator_calls == ['[data-sentinel-focus="1"]']
    screenshot_call = next(call for kind, call in page.calls if kind == "screenshot")
    assert screenshot_call["animations"] == "disabled"
    assert "full_page" not in screenshot_call
    assert "clip" not in screenshot_call
    assert path.exists()
