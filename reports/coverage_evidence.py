"""Build auditable, per-coverage-area evidence dossiers for Sentinel reports.

Execution status is kept separate from findings: a completed phase is not proof that
an entire standard category is secure. Evidence links are relative report artifacts.
"""
from __future__ import annotations

from collections import Counter
from typing import Any


def build_coverage_evidence_dossiers(
    coverage_rows: list[dict[str, Any]],
    findings: list[dict[str, Any]],
    phase_log: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Attach related findings, proof artifacts, phase diagnostics and limitations."""
    phase_by_name = {str(row.get("phase")): row for row in phase_log if row.get("phase")}
    dossiers: list[dict[str, Any]] = []
    for area in coverage_rows:
        area_id = str(area.get("id") or area.get("code") or "UNMAPPED")
        area_name = str(area.get("name") or area_id)
        phase_names = [str(p) for p in (area.get("phases") or []) if isinstance(p, str)]
        phase_rows = [dict(phase_by_name.get(name) or {"phase": name, "status": "not_run"}) for name in phase_names]
        tokens = {area_id.casefold(), area_name.casefold()}
        related = []
        for finding in findings:
            labels = " ".join(str(finding.get(key) or "") for key in ("coverage_id", "coverage_area", "standard", "category", "subcategory", "owasp_category", "title", "description")).casefold()
            finding_phases = {str(p) for p in (finding.get("phases") or finding.get("phase_names") or [])}
            # Prefer explicit mapping; use phase overlap only when the finding records it.
            if (area_id.casefold() in labels or area_name.casefold() in labels or
                    (phase_names and bool(finding_phases.intersection(phase_names)))):
                related.append(finding)
        counts = Counter(str(item.get("severity") or "Info").title() for item in related)
        evidence = []
        for finding in related:
            artifacts = finding.get("evidence_integrity_artifacts") or []
            paths = []
            for artifact in artifacts:
                if isinstance(artifact, dict):
                    path = artifact.get("relative_path") or artifact.get("path") or artifact.get("filename")
                    if path:
                        paths.append(str(path))
                elif isinstance(artifact, str):
                    paths.append(artifact)
            screenshot = finding.get("screenshot")
            if screenshot and not paths:
                paths.append(str(screenshot))
            evidence.append({
                "finding_id": finding.get("id"),
                "title": finding.get("title"),
                "severity": finding.get("severity", "Info"),
                "url": finding.get("url"),
                "method": finding.get("method"),
                "parameter": finding.get("parameter"),
                "observed": finding.get("evidence") or finding.get("observed") or finding.get("description"),
                "expected": finding.get("expected"),
                "actual": finding.get("actual"),
                "http_status": finding.get("http_status") or finding.get("status_code"),
                "request_evidence": finding.get("request_evidence"),
                "response_evidence": finding.get("response_evidence"),
                "artifacts": paths,
                "integrity_status": finding.get("evidence_integrity_status", "unknown"),
                "confidence": finding.get("confidence", "Unspecified"),
            })
        statuses = [str(row.get("status") or "not_run").lower() for row in phase_rows]
        completed = sum(status == "completed" for status in statuses)
        failed = sum(status in {"failed", "timed_out", "blocked", "error"} for status in statuses)
        not_run = sum(status in {"not_run", "skipped", "pending", "unknown"} for status in statuses)
        if not phase_names:
            status = "manual_review"
        elif failed:
            status = "partial_or_failed"
        elif not_run:
            status = "partial" if completed else "not_run"
        elif completed == len(statuses):
            status = "engines_completed"
        else:
            status = "partial"
        dossiers.append({
            "id": area_id,
            "standard": area.get("standard"),
            "name": area_name,
            "status": status,
            "phases": phase_rows,
            "phase_counts": {"total": len(phase_rows), "completed": completed, "failed": failed, "not_run_or_skipped": not_run},
            "finding_counts": {"total": len(related), "by_severity": dict(counts)},
            "findings": evidence,
            "evidence_count": sum(len(row["artifacts"]) for row in evidence),
            "limitations": area.get("limitation") or area.get("manual") or "Validate the observation manually; automated coverage does not prove absence of vulnerabilities.",
            "interpretation": "Engine execution status is not a security certification. Findings and artifacts require analyst validation; no finding means only that the configured checks did not report one.",
        })
    return dossiers
