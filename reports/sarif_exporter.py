"""Export Sentinel observations as SARIF 2.1.0 for CI/security tooling."""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from urllib.parse import urlsplit


SARIF_VERSION = "2.1.0"
RULE_PREFIX = "SENTINEL"


def _level(severity: object) -> str:
    value = str(severity or "info").strip().lower()
    if value in {"critical", "high"}:
        return "error"
    if value == "medium":
        return "warning"
    if value == "low":
        return "note"
    return "none"


def _safe_uri(value: object) -> str | None:
    raw = str(value or "").strip()
    if not raw:
        return None
    parsed = urlsplit(raw)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return None
    return raw


def build_sarif(report: dict) -> dict:
    """Build a SARIF document with stable rules and safe web locations."""
    findings = report.get("findings") or []
    rules: dict[str, dict] = {}
    results = []
    for item in findings:
        title = str(item.get("title") or "Unspecified observation").strip()
        category = str(item.get("category") or "General").strip()
        raw_id = str(item.get("id") or "")
        rule_id = (raw_id if raw_id.startswith(RULE_PREFIX + "-") else
                   RULE_PREFIX + "-" + "".join(ch if ch.isalnum() or ch in "-_" else "-" for ch in (raw_id or title).upper())[:80])
        rule_id = rule_id.strip("-") or "SENTINEL-OBSERVATION"
        severity = str(item.get("severity") or "Info")
        description = str(item.get("description") or item.get("impact") or title).strip()
        remediation = str(item.get("remediation") or item.get("fix") or "").strip()
        rule = rules.setdefault(rule_id, {
            "id": rule_id,
            "name": title[:200],
            "shortDescription": {"text": title[:500]},
            "fullDescription": {"text": description[:4000]},
            "defaultConfiguration": {"level": _level(severity)},
            "properties": {"category": category, "security-severity": {
                "Critical": "9.8", "High": "8.0", "Medium": "5.0", "Low": "2.0", "Info": "0.0"
            }.get(severity.title(), "0.0")},
        })
        message = description or title
        if remediation:
            message += "\\nRecommended remediation: " + remediation
        result = {
            "ruleId": rule_id,
            "ruleIndex": list(rules).index(rule_id),
            "level": _level(severity),
            "message": {"text": message[:6000]},
            "properties": {
                "severity": severity,
                "confidence": str(item.get("confidence") or "Medium"),
                "category": category,
                "sentinelFindingId": raw_id,
            },
        }
        uri = _safe_uri(item.get("url"))
        if uri:
            result["locations"] = [{
                "physicalLocation": {
                    "artifactLocation": {"uri": uri},
                }
            }]
        results.append(result)

    target = _safe_uri(report.get("target"))
    run = {
        "tool": {
            "driver": {
                "name": "Sentinel Web Security Assessment",
                "informationUri": "https://github.com/SanFlash/Penetration",
                "semanticVersion": str(report.get("framework_version") or "1.0"),
                "rules": list(rules.values()),
            }
        },
        "results": results,
        "properties": {
            "target": target or str(report.get("target") or ""),
            "generatedAt": str(report.get("generated_at") or datetime.now(timezone.utc).isoformat()),
            "coverageIsExecutionOnly": True,
            "note": "Automated results require validation; absence of findings is not proof of security.",
        },
    }
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": SARIF_VERSION,
        "runs": [run],
    }


def write_sarif(report: dict, path: str) -> str:
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(build_sarif(report), handle, indent=2, ensure_ascii=False)
    return path
