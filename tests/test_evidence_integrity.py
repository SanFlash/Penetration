import json

from scanners.evidence_integrity import validate_evidence, write_evidence_manifest


PNG = b"\x89PNG\r\n\x1a\n" + b"test-image-bytes"


def test_verified_screenshot_is_hashed_and_attached_to_finding(tmp_path):
    root = tmp_path / "evidence"
    root.mkdir()
    shot = root / "finding-1.png"
    shot.write_bytes(PNG)

    report = validate_evidence(
        [{"id": "F-1", "title": "Missing header", "screenshot": str(shot)}],
        root,
    )

    row = report["findings"][0]
    assert row["evidence_status"] == "verified_file"
    assert row["screenshots_verified"] == 1
    assert len(row["artifacts"][0]["sha256"]) == 64
    assert report["summary"]["findings_with_verified_screenshots"] == 1


def test_missing_and_invalid_screenshots_are_not_marked_verified(tmp_path):
    root = tmp_path / "evidence"
    root.mkdir()
    invalid = root / "bad.png"
    invalid.write_bytes(b"not an image")

    report = validate_evidence([
        {"id": "F-MISSING", "screenshot": str(root / "missing.png")},
        {"id": "F-INVALID", "screenshot": str(invalid)},
    ], root)

    assert [x["evidence_status"] for x in report["findings"]] == [
        "invalid_or_unavailable", "invalid_or_unavailable"
    ]
    statuses = [a["status"] for row in report["findings"] for a in row["artifacts"]]
    assert statuses == ["missing", "invalid_image_signature"]


def test_paths_outside_evidence_root_are_rejected(tmp_path):
    root = tmp_path / "evidence"
    root.mkdir()
    external = tmp_path / "outside.png"
    external.write_bytes(PNG)

    report = validate_evidence(
        [{"id": "F-OUT", "screenshot": str(external)}],
        root,
    )
    assert report["findings"][0]["artifacts"][0]["status"] == "outside_evidence_root"
    assert report["findings"][0]["evidence_status"] == "invalid_or_unavailable"


def test_manifest_writer_outputs_json(tmp_path):
    root = tmp_path / "evidence"
    root.mkdir()
    (root / "ok.png").write_bytes(PNG)
    output = tmp_path / "reports" / "evidence_integrity.json"

    report = write_evidence_manifest(
        [{"id": "F-1", "screenshots": [str(root / "ok.png")]}],
        root,
        output,
    )

    saved = json.loads(output.read_text(encoding="utf-8"))
    assert saved == report
    assert saved["schema_version"] == "1.0"
    assert saved["summary"]["artifact_files"] == 1


def test_mixed_screenshot_set_is_reported_as_partial_and_invalid_files_stay_referenced(tmp_path):
    root = tmp_path / "evidence"
    root.mkdir()
    valid = root / "valid.png"
    invalid = root / "invalid.png"
    valid.write_bytes(PNG)
    invalid.write_bytes(b"not an image")

    report = validate_evidence(
        [{"id": "F-PARTIAL", "screenshots": [str(valid), str(invalid)]}],
        root,
    )

    finding = report["findings"][0]
    assert finding["evidence_status"] == "partial"
    assert finding["screenshots_verified"] == 1
    assert finding["screenshots_invalid_or_unavailable"] == 1
    inventory = {row["path"]: row for row in report["artifacts"]}
    assert inventory["invalid.png"]["referenced_by_findings"] is True


def test_manifest_writer_rejects_output_inside_evidence_root(tmp_path):
    root = tmp_path / "evidence"
    root.mkdir()
    try:
        write_evidence_manifest([], root, root / "manifest.json")
    except ValueError as exc:
        assert "outside the evidence root" in str(exc)
    else:
        raise AssertionError("Manifest output inside the evidence root must be rejected")


def test_symlink_to_outside_evidence_is_rejected_when_supported(tmp_path):
    root = tmp_path / "evidence"
    root.mkdir()
    outside = tmp_path / "outside.png"
    outside.write_bytes(PNG)
    link = root / "outside-link.png"
    try:
        link.symlink_to(outside)
    except (OSError, NotImplementedError):
        return

    report = validate_evidence([{"id": "F-LINK", "screenshot": str(link)}], root)
    assert report["findings"][0]["evidence_status"] == "invalid_or_unavailable"
    assert report["findings"][0]["artifacts"][0]["status"] == "outside_evidence_root"
