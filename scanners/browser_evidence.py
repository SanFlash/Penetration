"""Chrome-only browser evidence capture for security findings."""
import json
import os
import re
from urllib.parse import urlparse

from playwright.sync_api import sync_playwright

from config import EVIDENCE_DIR
from utils.scope import assert_in_scope, assert_same_target


def _safe_filename(url: str) -> str:
    p = urlparse(url)
    value = p.netloc + p.path + ("_" + p.query if p.query else "")
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", value).strip("_")[:100] or "page"


def _marker(page, label: str) -> None:
    page.evaluate(
        """(label) => {
            const old = document.getElementById('__sentinel_security_evidence');
            if (old) old.remove();
            const box = document.createElement('div');
            box.id = '__sentinel_security_evidence';
            box.textContent = 'SENTINEL // SECURITY EVIDENCE — ' + label;
            Object.assign(box.style, {
                position:'fixed', top:'12px', left:'12px', zIndex:'2147483647',
                maxWidth:'calc(100vw - 24px)', padding:'10px 14px',
                background:'#101a2a', color:'#fff', border:'2px solid #38e8a0',
                borderRadius:'7px', font:'700 12px/1.35 monospace',
                boxShadow:'0 4px 18px rgba(0,0,0,.45)'
            });
            document.documentElement.appendChild(box);
        }""",
        label[:240],
    )


def capture_security_evidence(target: str, findings: list[dict], headed: bool = False,
                              slow_mo: int = 0, max_items: int = 30) -> list[dict]:
    """Capture visual evidence for active findings using Chromium and GET-only URLs."""
    assert_in_scope(target)
    os.makedirs(EVIDENCE_DIR, exist_ok=True)

    candidates = []
    seen = set()
    for finding in findings:
        url = finding.get("evidence_url") or finding.get("url")
        if not url or url in seen:
            continue
        try:
            assert_same_target(target, url)
        except Exception:
            continue
        if finding.get("severity") in {"Medium", "High", "Critical"} or finding.get("evidence_url"):
            candidates.append((url, finding.get("id", "security")))
            seen.add(url)
        if len(candidates) >= max_items:
            break

    captured = []
    if not candidates:
        with open(os.path.join(EVIDENCE_DIR, "security_browser_evidence.json"), "w", encoding="utf-8") as f:
            json.dump([], f, indent=2)
        return captured

    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=not headed, slow_mo=slow_mo)
        context = browser.new_context(viewport={"width": 1440, "height": 900})
        for index, (url, finding_id) in enumerate(candidates, 1):
            page = context.new_page()
            console_errors = []
            page.on("console", lambda msg: console_errors.append(msg.text) if msg.type == "error" else None)
            screenshot = None
            status = None
            error = None
            try:
                response = page.goto(url, wait_until="domcontentloaded", timeout=30000)
                status = response.status if response else None
                _marker(page, f"{finding_id} • HTTP {status}")
                screenshot = os.path.join(
                    EVIDENCE_DIR,
                    f"security_{index:03d}_{_safe_filename(url)}.png",
                )
                page.screenshot(path=screenshot, full_page=True)
            except Exception as exc:
                error = f"{type(exc).__name__}: {exc}"
                try:
                    _marker(page, f"{finding_id} • navigation failure")
                    screenshot = os.path.join(
                        EVIDENCE_DIR,
                        f"security_failure_{index:03d}_{_safe_filename(url)}.png",
                    )
                    page.screenshot(path=screenshot, full_page=True)
                except Exception as screenshot_exc:
                    error += f"; screenshot={type(screenshot_exc).__name__}: {screenshot_exc}"
                    screenshot = None
            finally:
                page.close()

            captured.append({
                "finding_id": finding_id,
                "url": url,
                "status": status,
                "screenshot": screenshot,
                "console_errors": console_errors[:20],
                "error": error,
            })
        context.close()
        browser.close()

    with open(os.path.join(EVIDENCE_DIR, "security_browser_evidence.json"), "w", encoding="utf-8") as f:
        json.dump(captured, f, indent=2, ensure_ascii=False)

    by_id = {item["finding_id"]: item for item in captured}
    for finding in findings:
        item = by_id.get(finding.get("id"))
        if item and item.get("screenshot"):
            finding["screenshot"] = item["screenshot"]
            finding["evidence_capture"] = item

    return captured
