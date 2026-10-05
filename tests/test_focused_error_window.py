from scanners.browser_evidence import _keywords


def test_security_evidence_keywords_ignore_generic_terms():
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


def test_security_evidence_keywords_are_bounded():
    finding = {
        "title": " ".join(["criticalword"] * 100),
        "evidence": " ".join(["differentword"] * 100),
    }
    assert _keywords(finding) == ["criticalword", "differentword"]
