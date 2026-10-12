"""Evidence integrity helpers for Sentinel security reports.

This module does not perform network requests. It validates captured artifacts
and creates a deterministic manifest so reports can distinguish missing,
invalid, and verified evidence from a merely referenced screenshot.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any


_IMAGE_SIGNATURES = {
    ".png": (b"\x89PNG\r\n\x1a\n",),
    ".jpg": (b"\xff\xd8\xff",),
    ".jpeg": (b"\xff\xd8\xff",),
    ".webp": (b"RIFF",),
}


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _inside_root(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except (ValueError, OSError):
        return False


def validate_evidence(
    findings: list[dict[str, Any]],
    evidence_root: str | os.PathLike[str],
) -> dict[str, Any]:
    """Validate screenshot references and return finding-level evidence status.

    Paths must resolve inside evidence_root. Image files are signature checked;
    a missing, empty, malformed, or out-of-root screenshot is never marked
    verified. This is an integrity check, not proof that the screenshot proves
    the vulnerability.
    """
    root = Path(evidence_root)
    records: list[dict[str, Any]] = []
    referenced: set[str] = set()

    for index, finding in enumerate(findings):
        finding_id = str(finding.get("id") or f"finding-{index + 1}")
        candidates = list(finding.get("screenshots") or [])
        if finding.get("screenshot"):
            candidates.append(finding["screenshot"])
        candidates = list(dict.fromkeys(str(p) for p in candidates if p))
        artifacts = []

        for raw_path in candidates:
            path = Path(raw_path)
            if not path.is_absolute():
                path = root / path
            artifact: dict[str, Any] = {
                "path": str(raw_path),
                "status": "missing",
                "sha256": None,
                "size_bytes": 0,
            }
            if not _inside_root(path, root):
                artifact["status"] = "outside_evidence_root"
            elif not path.is_file():
                artifact["status"] = "missing"
            else:
                size = path.stat().st_size
                artifact["size_bytes"] = size
                suffix = path.suffix.lower()
                signatures = _IMAGE_SIGNATURES.get(suffix)
                with path.open("rb") as stream:
                    header = stream.read(12)
                signature_ok = bool(signatures) and any(header.startswith(sig) for sig in signatures)
                if size == 0:
                    artifact["status"] = "empty"
                elif not signature_ok:
                    artifact["status"] = "invalid_image_signature"
                else:
                    artifact["status"] = "verified_file"
                    artifact["sha256"] = _sha256(path)
                    referenced.add(str(path.resolve()))
            artifacts.append(artifact)

        verified = sum(1 for item in artifacts if item["status"] == "verified_file")
        records.append({
            "finding_id": finding_id,
            "title": str(finding.get("title") or "Untitled finding"),
            "evidence_status": (
                "verified_file" if verified else
                "missing" if not artifacts else
                "invalid_or_unavailable"
            ),
            "screenshots_expected": len(candidates),
            "screenshots_verified": verified,
            "artifacts": artifacts,
        })

    all_files = []
    if root.is_dir():
        for path in sorted(root.rglob("*")):
            if path.is_file() and _inside_root(path, root):
                all_files.append({
                    "path": path.relative_to(root).as_posix(),
                    "size_bytes": path.stat().st_size,
                    "sha256": _sha256(path),
                    "referenced_by_findings": str(path.resolve()) in referenced,
                })

    return {
        "schema_version": "1.0",
        "evidence_root": root.name,
        "findings": records,
        "artifacts": all_files,
        "summary": {
            "findings": len(records),
            "findings_with_verified_screenshots": sum(
                row["evidence_status"] == "verified_file" for row in records
            ),
            "findings_missing_or_invalid_evidence": sum(
                row["evidence_status"] != "verified_file" for row in records
            ),
            "artifact_files": len(all_files),
        },
        "limitations": [
            "File integrity does not establish that an artifact proves a vulnerability.",
            "Screenshots may contain sensitive data and must be reviewed before sharing.",
            "Only screenshot file signatures and hashes are checked; semantic evidence review remains necessary.",
        ],
    }


def write_evidence_manifest(
    findings: list[dict[str, Any]],
    evidence_root: str | os.PathLike[str],
    output_path: str | os.PathLike[str],
) -> dict[str, Any]:
    """Write the evidence integrity manifest as UTF-8 JSON."""
    report = validate_evidence(findings, evidence_root)
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return report
