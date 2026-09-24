from scanners.active_security import _query_canary, _REFLECTION_MARKER
from scanners.compatibility import BROWSERS


def test_active_canary_rewrites_first_query_parameter():
    url, parameter = _query_canary("https://amwebtech.com/search?q=test&x=1")
    assert parameter == "q"
    assert _REFLECTION_MARKER in url
    assert "x=1" in url


def test_active_canary_requires_query_parameters():
    url, parameter = _query_canary("https://amwebtech.com/about")
    assert url is None
    assert parameter is None


def test_chrome_only_browser_matrix():
    assert BROWSERS == ("chromium",)
