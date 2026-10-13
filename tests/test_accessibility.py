from scanners.accessibility import evaluate_accessibility_snapshot


def test_clean_accessibility_snapshot_has_no_findings():
    snapshot = {
        "document_language": "en",
        "title_present": True,
        "missing_alt_count": 0,
        "unlabeled_controls": 0,
        "unlabeled_links": 0,
        "unlabeled_buttons": 0,
        "main_landmark_present": True,
        "heading_level_skips": 0,
        "duplicate_id_count": 0,
        "keyboard_inaccessible_custom_controls": 0,
        "low_contrast_samples": [],
    }
    assert evaluate_accessibility_snapshot(snapshot, "https://example.com/") == []


def test_accessibility_snapshot_emits_wcag_mapped_findings():
    snapshot = {
        "document_language": "",
        "title_present": False,
        "missing_alt_count": 2,
        "unlabeled_controls": 1,
        "unlabeled_links": 3,
        "unlabeled_buttons": 1,
        "main_landmark_present": False,
        "heading_level_skips": 1,
        "duplicate_id_count": 2,
        "keyboard_inaccessible_custom_controls": 1,
        "low_contrast_samples": [
            {"text": "Light gray text", "ratio": 2.2, "foreground": "rgb(210, 210, 210)", "background": "rgb(255, 255, 255)"}
        ],
    }
    findings = evaluate_accessibility_snapshot(snapshot, "https://example.com/")
    by_id = {finding["id"].split("-")[1]: finding for finding in findings}

    assert len(findings) == 10
    assert "WCAG 2.2 - 1.1.1" in by_id["ALT"]["standard_refs"]
    assert by_id["LINK"]["severity"] == "Medium"
    assert by_id["CONTRAST"]["confidence"] == "Medium"
    assert all(finding["manual_validation_required"] for finding in findings)
    assert all(finding["url"] == "https://example.com/" for finding in findings)


def test_accessibility_finding_ids_are_stable_for_same_page_and_rule():
    snapshot = {"document_language": ""}
    first = evaluate_accessibility_snapshot(snapshot, "https://example.com/")
    second = evaluate_accessibility_snapshot(snapshot, "https://example.com/")

    assert first[0]["id"] == second[0]["id"]
    assert first[0]["standard"] == "WCAG 2.2"
    assert first[0]["manual_validation_required"] is True


def test_accessibility_snapshot_accepts_missing_or_partial_data_safely():
    findings = evaluate_accessibility_snapshot(None, "https://example.com/")
    rules = {finding["id"].split("-")[1] for finding in findings}

    assert "LANG" in rules
    assert "TITLE" in rules
    assert "ALT" not in rules
