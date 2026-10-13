"""Lightweight browser-snapshot accessibility checks aligned to WCAG 2.2.

These checks are triage heuristics, not a WCAG conformance audit. Browser-only
checks cannot prove screen-reader usability or replace assistive-technology and
human review. Input is a JSON-serializable snapshot collected on the page.
"""
from __future__ import annotations

import hashlib
from typing import Any


def _finding_id(url: str, rule: str) -> str:
    digest = hashlib.sha1(f"{url}|{rule}".encode("utf-8")).hexdigest()[:10].upper()
    return f"A11Y-{rule.upper()}-{digest}"


def evaluate_accessibility_snapshot(snapshot: dict[str, Any] | None, url: str) -> list[dict[str, Any]]:
    """Convert an accessibility snapshot into deterministic, evidence-backed findings."""
    data = snapshot if isinstance(snapshot, dict) else {}
    findings: list[dict[str, Any]] = []

    def add(rule: str, title: str, count: int, severity: str, wcag: str,
            evidence: str, detail: str, impact: str, remediation: str,
            confidence: str = "High") -> None:
        if count <= 0:
            return
        findings.append({
            "id": _finding_id(url, rule),
            "title": title,
            "severity": severity,
            "confidence": confidence,
            "category": "Accessibility",
            "method": "Browser DOM inspection",
            "url": url,
            "evidence": evidence,
            "detail": detail,
            "impact": impact,
            "remediation": remediation,
            "standard": "WCAG 2.2",
            "standard_refs": [wcag],
            "automated_check": True,
            "manual_validation_required": True,
        })

    if not data.get("document_language"):
        add("LANG", "Document language is not declared", 1, "Low", "WCAG 2.2 - 3.1.1",
            "The root <html> element has no non-empty lang attribute.",
            "Assistive technologies use the document language to select pronunciation and language rules.",
            "Screen-reader output may be pronounced using the wrong language.",
            "Set an accurate lang attribute on the root html element and mark language changes within the page.")

    if not data.get("title_present"):
        add("TITLE", "Document title is missing", 1, "Low", "WCAG 2.2 - 2.4.2",
            "document.title is empty after navigation.",
            "The page does not expose a meaningful document title.",
            "Users may have difficulty identifying the page in tabs, history, and assistive-technology navigation.",
            "Provide a unique, descriptive title for each page.")

    add("ALT", "Images missing alternative text", int(data.get("missing_alt_count") or 0),
        "Medium", "WCAG 2.2 - 1.1.1",
        f"Images without an alt attribute: {int(data.get('missing_alt_count') or 0)}.",
        "Image elements do not expose an explicit text alternative. Decorative images should use alt=\"\".",
        "Users who cannot see images may miss information conveyed by informative graphics.",
        "Provide meaningful alt text for informative images and an empty alt attribute for decorative images.")

    add("CONTROL-NAME", "Form controls may lack accessible names", int(data.get("unlabeled_controls") or 0),
        "Medium", "WCAG 2.2 - 4.1.2",
        f"Controls without a detected label, aria-label, aria-labelledby, or title: {int(data.get('unlabeled_controls') or 0)}.",
        "The DOM heuristic did not find an accessible-name source for one or more form controls.",
        "Assistive-technology users may not know what a control does or what input it expects.",
        "Use a visible label associated with each control, or provide a valid accessible name.")

    add("LINK-NAME", "Links may lack accessible names", int(data.get("unlabeled_links") or 0),
        "Medium", "WCAG 2.2 - 2.4.4",
        f"Links with href but no detected text, aria label, title, or named image: {int(data.get('unlabeled_links') or 0)}.",
        "One or more links appear to have no programmatically determinable name.",
        "Users may encounter links whose destination or purpose is unclear.",
        "Give each link descriptive text or a valid accessible name; ensure linked images have useful alt text.")

    add("BUTTON-NAME", "Buttons may lack accessible names", int(data.get("unlabeled_buttons") or 0),
        "Medium", "WCAG 2.2 - 4.1.2",
        f"Buttons without detected text or accessible-name attributes: {int(data.get('unlabeled_buttons') or 0)}.",
        "One or more button elements appear to have no programmatically determinable name.",
        "Users of assistive technology may not be able to identify the action.",
        "Provide visible button text or a valid accessible name, and verify the name in a screen reader.")

    add("MAIN-LANDMARK", "Main content landmark not detected", int(not data.get("main_landmark_present", True)),
        "Low", "WCAG 2.2 - 2.4.1",
        "No <main> element or role=main landmark was found.",
        "A main landmark can help users navigate directly to the primary content.",
        "Keyboard and screen-reader users may need to traverse more repeated content to reach the main area.",
        "Identify the primary page content with one appropriate main landmark where the page structure supports it.",
        confidence="Medium")

    add("HEADING-ORDER", "Heading hierarchy has skipped levels", int(data.get("heading_level_skips") or 0),
        "Low", "WCAG 2.2 - 1.3.1",
        f"Potential heading-level skips detected: {int(data.get('heading_level_skips') or 0)}.",
        "A heading level increases by more than one between consecutive headings. This is a structural warning, not proof of a WCAG failure.",
        "A confusing heading outline can make it harder to understand and navigate page structure.",
        "Review the heading outline and use levels that reflect the content hierarchy.",
        confidence="Medium")

    add("DUPLICATE-ID", "Duplicate HTML IDs detected", int(data.get("duplicate_id_count") or 0),
        "Medium", "WCAG 2.2 - 4.1.2",
        f"Duplicate id values detected: {int(data.get('duplicate_id_count') or 0)}.",
        "Duplicate IDs can cause labels, descriptions, and ARIA references to resolve to the wrong element.",
        "Assistive technology may announce an incorrect name or relationship.",
        "Ensure every id is unique and update label and ARIA references to the intended element.")

    add("KEYBOARD", "Custom interactive controls may not be keyboard reachable", int(data.get("keyboard_inaccessible_custom_controls") or 0),
        "Medium", "WCAG 2.2 - 2.1.1",
        f"Custom interactive elements with negative tabIndex detected: {int(data.get('keyboard_inaccessible_custom_controls') or 0)}.",
        "Elements using common interactive ARIA roles were detected with tabIndex below zero.",
        "Keyboard-only users may be unable to reach or operate the control.",
        "Prefer native buttons and links; otherwise implement correct focusability, keyboard activation, and state semantics.",
        confidence="Medium")

    contrast = data.get("low_contrast_samples") or []
    if contrast:
        examples = "; ".join(
            f"{str(item.get('text', 'text'))[:45]!r} ratio={item.get('ratio')} "
            f"(fg={item.get('foreground')}, bg={item.get('background')})"
            for item in contrast[:5] if isinstance(item, dict)
        )
        add("CONTRAST", "Potential low-contrast text detected", len(contrast),
            "Medium", "WCAG 2.2 - 1.4.3",
            f"Potential contrast failures: {len(contrast)}. Samples: {examples or 'See page snapshot.'}",
            "Computed foreground/background colors suggest text may fall below the WCAG contrast threshold. Transparent layers, images, gradients, and browser rendering can make this estimate incomplete.",
            "Text may be difficult to read for users with low vision or in challenging lighting.",
            "Measure the actual rendered colors, meet 4.5:1 for normal text and 3:1 for large text, and verify with a dedicated accessibility tool.",
            confidence="Medium")

    return findings
