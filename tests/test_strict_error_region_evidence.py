from scanners.browser_evidence import _focused_screenshot


class FakePage:
    viewport_size = {"width": 1440, "height": 900}

    def __init__(self):
        self.calls = []

    def screenshot(self, **kwargs):
        self.calls.append(kwargs)


def test_no_focus_never_captures_viewport():
    page = FakePage()
    result = _focused_screenshot(page, "unused.png", None)

    assert result["mode"] == "no-focused-region"
    assert result["focus_found"] is False
    assert page.calls == []


def test_focus_uses_tight_clip_only():
    page = FakePage()
    focus = {
        "x": 600,
        "y": 350,
        "width": 180,
        "height": 90,
        "tag": "div",
        "id": "error",
        "className": "error-message",
        "text": "Access denied",
        "hits": ["access", "denied"],
        "errorWords": 1,
    }

    result = _focused_screenshot(page, "evidence.png", focus)

    assert result["mode"] == "focused-error-region"
    assert len(page.calls) == 1
    call = page.calls[0]
    assert call["full_page"] is False
    assert call["clip"]["width"] <= 760
    assert call["clip"]["height"] <= 520
    assert call["clip"]["width"] < page.viewport_size["width"]
    assert call["clip"]["height"] < page.viewport_size["height"]
