"""Portable HTML/PDF export helpers for assessment reports.

The portable HTML embeds visual evidence images as data URIs so the report can be
shared as one file without the local evidence/ directory. PDF export uses the
already-supported Playwright/Chromium runtime when available and exposes every
report tab through print CSS.
"""
from __future__ import annotations

import base64
import mimetypes
import os
import re
from pathlib import Path


_IMAGE_RE = re.compile(
    r'(?P<prefix>(?:src|href)=["\'])(?P<path>[^"\']+)(?P<suffix>["\'])',
    re.IGNORECASE,
)


def _image_data_uri(path: Path) -> str | None:
    if not path.is_file():
        return None
    mime, _ = mimetypes.guess_type(path.name)
    if not mime or not mime.startswith("image/"):
        return None
    try:
        encoded = base64.b64encode(path.read_bytes()).decode("ascii")
    except OSError:
        return None
    return f"data:{mime};base64,{encoded}"


def _resolve_report_asset(report_html: Path, asset: str) -> Path | None:
    if not asset or asset.startswith(("data:", "#", "http://", "https://", "mailto:")):
        return None
    clean = asset.split("#", 1)[0].split("?", 1)[0]
    if not clean:
        return None
    candidate = (report_html.parent / clean).resolve()
    try:
        candidate.relative_to(report_html.parent.parent.resolve())
    except ValueError:
        return None
    return candidate


def make_portable_html(report_html_path: str, output_path: str | None = None) -> str:
    """Create a single-file HTML report with local image evidence embedded."""
    source = Path(report_html_path).resolve()
    if not source.is_file():
        raise FileNotFoundError(source)

    output = Path(output_path or source.with_name("report_portable.html")).resolve()
    document = source.read_text(encoding="utf-8")

    embedded = 0
    seen: set[str] = set()

    def replace(match: re.Match[str]) -> str:
        nonlocal embedded
        asset = match.group("path")
        if asset in seen:
            return match.group(0)
        seen.add(asset)
        path = _resolve_report_asset(source, asset)
        if not path:
            return match.group(0)
        uri = _image_data_uri(path)
        if not uri:
            return match.group(0)
        embedded += 1
        return match.group("prefix") + uri + match.group("suffix")

    document = _IMAGE_RE.sub(replace, document)

    # The original report is intentionally retained as the live/local report.
    # This marker lets recipients see that evidence is embedded in this copy.
    marker = (
        '<meta name="sentinel-report-mode" content="portable-single-file">'
        f'<meta name="sentinel-embedded-images" content="{embedded}">'
    )
    document = document.replace("</head>", marker + "</head>", 1)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(document, encoding="utf-8")
    return str(output)


def make_pdf(report_html_path: str, output_path: str | None = None) -> str | None:
    """Render every report tab to PDF through Playwright/Chromium.

    Returns None when Playwright/Chromium is unavailable; callers can still
    distribute report_portable.html or use the browser's Print -> Save as PDF.
    """
    source = Path(report_html_path).resolve()
    output = Path(output_path or source.with_name("report.pdf")).resolve()
    output.parent.mkdir(parents=True, exist_ok=True)

    try:
        from playwright.sync_api import sync_playwright
    except Exception:
        return None

    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True)
            page = browser.new_page()
            page.goto(source.as_uri(), wait_until="networkidle")
            page.emulate_media(media="print")
            page.pdf(
                path=str(output),
                format="A4",
                print_background=True,
                margin={"top": "10mm", "right": "8mm", "bottom": "10mm", "left": "8mm"},
            )
            browser.close()
    except Exception:
        return None

    return str(output) if output.is_file() else None
