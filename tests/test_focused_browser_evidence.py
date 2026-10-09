from scanners.browser_evidence import _keywords


def test_keywords_extract_distinctive_error_terms():
    finding = {
        "title": "Authorization failure: protected order exposed",
        "evidence": "Unauthorized account received protected object",
        "detail": "HTTP 403 error",
    }
    keywords = _keywords(finding)
    assert "authorization" not in keywords
    assert "protected" in keywords
    assert "order" in keywords
    assert len(keywords) <= 12


def test_keywords_are_bounded_and_deterministic():
    finding = {
        "title": " ".join(["criticalword"] * 100),
        "evidence": " ".join(["differentword"] * 100),
    }
    assert _keywords(finding) == ["criticalword", "differentword"]


def test_evidence_candidates_keep_multiple_findings_on_same_url():
    from scanners.browser_evidence import _evidence_candidates

    url = "https://example.com/account"
    findings = [
        {
            "id": "SEC-HEADER-1",
            "title": "Missing security response headers",
            "severity": "Medium",
            "url": url,
        },
        {
            "id": "SEC-COOKIE-2",
            "title": "Cookie missing HttpOnly attribute",
            "severity": "High",
            "url": url,
        },
        {
            "id": "SEC-COOKIE-2",
            "title": "Cookie missing HttpOnly attribute",
            "severity": "High",
            "url": url,
        },
    ]

    candidates = _evidence_candidates(url, findings, max_items=10)

    assert len(candidates) == 2
    assert {candidate[1] for candidate in candidates} == {
        "SEC-HEADER-1",
        "SEC-COOKIE-2",
    }
    assert all(candidate[0] == url for candidate in candidates)


def test_evidence_candidate_limit_is_respected():
    from scanners.browser_evidence import _evidence_candidates

    url = "https://example.com/"
    findings = [
        {
            "id": f"SEC-{index}",
            "title": f"Security finding {index}",
            "severity": "High",
            "url": url,
        }
        for index in range(5)
    ]

    candidates = _evidence_candidates(url, findings, max_items=3)

    assert len(candidates) == 3


def test_network_filter_ignores_aborted_google_analytics_beacon():
    from scanners.compatibility import _request_failure_is_actionable

    page = "https://example.com/contact"
    assert not _request_failure_is_actionable(
        "POST https://www.google.com/ccm/collect?tid=abc: net::ERR_ABORTED", page
    )
    assert not _request_failure_is_actionable(
        "POST https://www.google-analytics.com/g/collect?v=2: net::ERR_FAILED", page
    )


def test_network_filter_keeps_first_party_api_failure():
    from scanners.compatibility import _request_failure_is_actionable

    assert _request_failure_is_actionable(
        "GET https://example.com/api/profile: net::ERR_CONNECTION_RESET",
        "https://example.com/dashboard",
    )
