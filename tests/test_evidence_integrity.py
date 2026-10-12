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
