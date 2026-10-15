"""Validate screenshot artifacts and produce a resilient evidence-integrity ledger.

This module performs local filesystem inspection only. Hashes and image signatures
help detect missing or altered files; they do not prove that an image supports a
finding or that the finding is exploitable.
"""
from __future__ import annotations

import hashlib
import json
import os
import stat
from pathlib import Path
from typing import Any


_IMAGE_SIGNATURES = {
    ".png": (b"\\x89PNG\\r\\n\\x1a\\n",),
    ".jpg": (b"\\xff\\xd8\\xff",),
    ".jpeg": (b"\\xff\\xd8\\xff",),
    ".webp": (b"RIFF",),
}


def _read_artifact(path: Path) -> tuple[int, str, bytes]:
    """Read a regular file through one descriptor and return size, digest and header."""
    flags = os.O_RDONLY
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(str(path), flags)
    digest = hashlib.sha256()
    header = b""
    size = 0
    try:
        file_stat = os.fstat(descriptor)
        if not stat.S_ISREG(file_stat.st_mode):
            raise OSError("Evidence artifact is not a regular file")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            while True:
                chunk = stream.read(1024 * 1024)
                if not chunk:
                    break
                if len(header) < 16:
                    header += chunk[:16 - len(header)]
                digest.update(chunk)
                size += len(chunk)
        return size, digest.hexdigest(), header
    finally:
        os.close(descriptor)


def _signature_valid(path: Path, header: bytes) -> bool:
    signatures = _IMAGE_SIGNATURES.get(path.suffix.lower())
    if not signatures or not any(header.startswith(signature) for signature in signatures):
        return False
    if path.suffix.lower() == ".webp":
        return len(header) >= 12 and header[8:12] == b"WEBP"
    return True


def _artifact_record(raw_path: str, root: Path) -> tuple[dict[str, Any], str | None]:
    """Validate one screenshot, rejecting paths outside the evidence root."""
    candidate = Path(raw_path)
    if not candidate.is_absolute():
        candidate = root / candidate
    record: dict[str, Any] = {
        "path": raw_path, "status": "missing", "sha256": None, "size_bytes": 0,
    }
    try:
        root_resolved = root.resolve(strict=False)
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(root_resolved)
        size, digest, header = _read_artifact(resolved)
        record["size_bytes"] = size
        if size == 0:
            record["status"] = "empty"
        elif not _signature_valid(resolved, header):
            record["status"] = "invalid_image_signature"
        else:
            record["status"] = "verified_file"
            record["sha256"] = digest
        return record, str(resolved)
    except ValueError:
        record["status"] = "outside_evidence_root"
    except FileNotFoundError:
        record["status"] = "missing"
    except (OSError, RuntimeError) as exc:
        record["status"] = "unavailable"
        record["error"] = f"{type(exc).__name__}: {exc}"
    return record, None


def validate_evidence(
    findings: list[dict[str, Any]],
    evidence_root: str | os.PathLike[str],
    *,
    exclude_paths: list[str | os.PathLike[str]] | None = None,
) -> dict[str, Any]:
    """Validate screenshots and inventory files without aborting on individual I/O errors.

    Mixed verified and invalid/missing artifacts receive a partial status. Symlinks
    resolving outside the root are rejected. Excluded paths are omitted from inventory.
    """
    root = Path(evidence_root)
    root_resolved = root.resolve(strict=False)
    excluded: set[str] = set()
    for value in exclude_paths or []:
        try:
            excluded.add(str(Path(value).resolve(strict=False)))
        except (OSError, RuntimeError):
            continue

    records: list[dict[str, Any]] = []
    referenced: set[str] = set()
    inventory_errors: list[dict[str, str]] = []

    for index, finding in enumerate(findings):
        finding_id = str(finding.get("id") or finding.get("issue_id") or f"finding-{index + 1}")
        candidates = list(finding.get("screenshots") or [])
        if finding.get("screenshot"):
            candidates.append(finding["screenshot"])
        candidates = list(dict.fromkeys(str(value) for value in candidates if value))
        artifacts = []
        for raw_path in candidates:
            artifact, canonical = _artifact_record(raw_path, root)
            artifacts.append(artifact)
            if canonical:
                referenced.add(canonical)

        verified = sum(artifact["status"] == "verified_file" for artifact in artifacts)
        invalid = sum(artifact["status"] != "verified_file" for artifact in artifacts)
        if verified and invalid:
            status = "partial"
        elif verified:
            status = "verified_file"
        elif not artifacts:
            status = "missing"
        else:
            status = "invalid_or_unavailable"
        records.append({
            "finding_id": finding_id,
            "title": str(finding.get("title") or "Untitled finding"),
            "evidence_status": status,
            "screenshots_expected": len(candidates),
            "screenshots_verified": verified,
            "screenshots_invalid_or_unavailable": invalid,
            "artifacts": artifacts,
        })

    inventory: list[dict[str, Any]] = []
    if root.is_dir():
        try:
            paths = sorted(root.rglob("*"))
        except OSError as exc:
            paths = []
            inventory_errors.append({"path": str(root), "error": f"{type(exc).__name__}: {exc}"})
        for path in paths:
            try:
                if path.is_symlink() or not path.is_file():
                    continue
                resolved = path.resolve(strict=True)
                resolved.relative_to(root_resolved)
                if str(resolved) in excluded:
                    continue
                size, digest, _ = _read_artifact(resolved)
                inventory.append({
                    "path": path.relative_to(root).as_posix(),
                    "size_bytes": size,
                    "sha256": digest,
                    "referenced_by_findings": str(resolved) in referenced,
                })
            except (OSError, ValueError, RuntimeError) as exc:
                inventory_errors.append({
                    "path": str(path), "error": f"{type(exc).__name__}: {exc}",
                })

    return {
        "schema_version": "1.1",
        "evidence_root": root.name,
        "findings": records,
        "artifacts": inventory,
        "inventory_errors": inventory_errors,
        "summary": {
            "findings": len(records),
            "findings_with_verified_screenshots": sum(
                row["evidence_status"] == "verified_file" for row in records
            ),
            "findings_with_partial_evidence": sum(
                row["evidence_status"] == "partial" for row in records
            ),
            "findings_missing_or_invalid_evidence": sum(
                row["evidence_status"] in {"missing", "invalid_or_unavailable"} for row in records
            ),
            "artifact_files": len(inventory),
            "inventory_errors": len(inventory_errors),
        },
        "limitations": [
            "File integrity does not establish that an artifact proves a vulnerability.",
            "Screenshots may contain sensitive data and must be reviewed before sharing.",
            "Image signatures and hashes are checked; semantic evidence review remains necessary.",
            "Unreadable or changing files are reported as unavailable instead of aborting the manifest.",
        ],
    }


def write_evidence_manifest(
    findings: list[dict[str, Any]],
    evidence_root: str | os.PathLike[str],
    output_path: str | os.PathLike[str],
) -> dict[str, Any]:
    """Write the evidence integrity manifest outside the evidence root."""
    root = Path(evidence_root).resolve(strict=False)
    output = Path(output_path).resolve(strict=False)
    try:
        output.relative_to(root)
    except ValueError:
        pass
    else:
        raise ValueError("Evidence manifest output must be outside the evidence root")

    report = validate_evidence(findings, evidence_root, exclude_paths=[output])
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\\n", encoding="utf-8")
    return report
