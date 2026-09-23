"""Safe browser compatibility checks with optional live telemetry."""
import json
import os
from urllib.parse import urlparse

from playwright.sync_api import sync_playwright, TimeoutError as PlaywrightTimeoutError

from config import EVIDENCE_DIR
from utils.scope import assert_in_scope

VIEWPORTS = {
    "mobile-small": {"width": 375, "height": 812},
    "mobile-large": {"width": 390, "height": 844},
    "tablet": {"width": 768, "height": 1024},
    "laptop": {"width": 1366, "height": 768},
    "desktop": {"width": 1440, "height": 900},
    "large-desktop": {"width": 1920, "height": 1080},
}
BROWSERS = ("chromium", "firefox", "webkit")


def _safe_filename(url: str) -> str:
    parsed = urlparse(url)
    value = parsed.netloc + parsed.path + ("_" + parsed.query if parsed.query else "")
    return "".join(ch if ch.isalnum() else "_" for ch in value).strip("_")[:120] or "page"


def _page_findings(url, browser_name, viewport_name, data):
    findings = []
    prefix = f"{browser_name}/{viewport_name}"
    for error in data["console_errors"]:
        findings.append({
            "id": f"COMP-CONSOLE-{abs(hash((url, prefix, error))) % 100000:05d}",
            "title": "Browser console error", "severity": "Low", "confidence": "High",
            "category": "Compatibility", "method": "GET", "url": url,
            "evidence": f"{prefix}: {error}",
            "detail": "The page emitted a browser console error during automated navigation.",
            "impact": "Console errors can indicate broken JavaScript, failed integrations, or client-side functionality that may not work correctly for users.",
            "remediation": "Inspect the originating JavaScript error and fix the failing client-side code or dependency.",
        })
    for failure in data["request_failures"]:
        findings.append({
            "id": f"COMP-NET-{abs(hash((url, prefix, failure))) % 100000:05d}",
            "title": "Failed browser network request", "severity": "Medium", "confidence": "High",
            "category": "Compatibility", "method": "GET", "url": url,
            "evidence": f"{prefix}: {failure}",
            "detail": "A browser resource request failed while loading the page.",
            "impact": "Failed assets or API requests can produce broken UI, missing content, or incomplete user workflows.",
            "remediation": "Inspect the failed resource, HTTP status, CORS policy, DNS/TLS configuration, and deployment path.",
        })
    if data["horizontal_overflow"]:
        findings.append({
            "id": f"COMP-OVERFLOW-{abs(hash((url, viewport_name))) % 100000:05d}",
            "title": "Horizontal overflow at responsive viewport", "severity": "Medium", "confidence": "High",
            "category": "Responsive UI", "method": "GET", "url": url,
            "evidence": f"{prefix}: document scrollWidth={data['scroll_width']} viewportWidth={data['viewport_width']}",
            "detail": "The document is wider than the viewport and may require horizontal scrolling.",
            "impact": "Horizontal overflow can hide content or make mobile and narrow-screen interfaces difficult to use.",
            "remediation": "Inspect fixed widths, oversized media, long unbroken content, positioned elements, and container overflow rules.",
        })
    if data["missing_alt_count"]:
        findings.append({
            "id": f"COMP-ALT-{abs(hash((url, data['missing_alt_count']))) % 100000:05d}",
            "title": "Images missing alternative text", "severity": "Low", "confidence": "High",
            "category": "Accessibility", "cwe": "CWE-116", "url": url,
            "evidence": f"{data['missing_alt_count']} image element(s) without an alt attribute.",
            "detail": "Images without appropriate alternative text can be inaccessible to screen-reader users.",
            "impact": "Important visual information may not be available to users relying on assistive technology.",
            "remediation": "Provide meaningful alt text for informative images and an empty alt attribute for purely decorative images.",
        })
    if data["unlabeled_controls"]:
        findings.append({
            "id": f"COMP-LABEL-{abs(hash((url, data['unlabeled_controls']))) % 100000:05d}",
            "title": "Potentially unlabeled form controls", "severity": "Low", "confidence": "Medium",
            "category": "Accessibility", "url": url,
            "evidence": f"{data['unlabeled_controls']} form control(s) could not be associated with a label.",
            "detail": "Automated markup inspection found controls without an obvious associated label.",
            "impact": "Users of assistive technology may have difficulty identifying the purpose of controls.",
            "remediation": "Associate each control with a visible label or an appropriate accessible name.",
        })
    return findings


def run_compatibility(target: str, urls: list[str], max_pages: int = 12,
                      headed: bool = False, slow_mo: int = 0, telemetry=None) -> dict:
    assert_in_scope(target)
    os.makedirs(EVIDENCE_DIR, exist_ok=True)
    urls = list(dict.fromkeys(urls))[:max_pages]
    results, findings, unavailable = [], [], []
    total = max(1, len(urls) * len(BROWSERS) * len(VIEWPORTS))
    completed = 0

    def emit(**payload):
        if telemetry:
            telemetry(**payload)

    emit(stage="BROWSER ENGINE INITIALIZATION", detail="Preparing Playwright browser matrix.", progress=0,
         log={"time": "00:00", "level": "ok", "message": "Compatibility engine initialized."})

    with sync_playwright() as pw:
        for browser_name in BROWSERS:
            emit(browser=browser_name.upper(), stage=f"{browser_name.upper()} ENGINE",
                 detail=f"Launching {browser_name}.")
            try:
                browser_type = getattr(pw, browser_name)
                browser = browser_type.launch(headless=not headed, slow_mo=slow_mo)
            except Exception as exc:
                unavailable.append({"browser": browser_name, "reason": str(exc)})
                emit(stage=f"{browser_name.upper()} UNAVAILABLE", detail=str(exc),
                     log={"time": "", "level": "warn", "message": f"{browser_name} unavailable: {exc}"})
                continue

            for viewport_name, viewport in VIEWPORTS.items():
                context = browser.new_context(viewport=viewport)
                for url in urls:
                    assert_in_scope(url)
                    page = context.new_page()
                    console_errors, request_failures = [], []
                    page.on("console", lambda msg: console_errors.append(msg.text) if msg.type == "error" else None)
                    page.on("requestfailed", lambda req: request_failures.append(f"{req.method} {req.url}: {req.failure}"))
                    emit(browser=browser_name.upper(), viewport=viewport_name,
                         stage="NAVIGATING", detail=url,
                         log={"time": "", "level": "", "message": f"[{browser_name}/{viewport_name}] {url}"})
                    try:
                        response = page.goto(url, wait_until="domcontentloaded", timeout=30000)
                        try:
                            page.wait_for_load_state("networkidle", timeout=5000)
                        except PlaywrightTimeoutError:
                            pass
                        metrics = page.evaluate("""() => ({
                            viewportWidth: window.innerWidth,
                            scrollWidth: document.documentElement.scrollWidth,
                            missingAltCount: [...document.images].filter(i => !i.hasAttribute('alt')).length,
                            unlabeledControls: [...document.querySelectorAll('input,select,textarea,button')].filter(el => {
                              if (el.tagName === 'INPUT' && ['hidden','submit','button','reset','image'].includes(el.type)) return false;
                              if (el.labels && el.labels.length) return false;
                              if (el.getAttribute('aria-label') || el.getAttribute('aria-labelledby') || el.title) return false;
                              return true;
                            }).length,
                            titlePresent: !!document.title.trim(),
                            loadTiming: performance.getEntriesByType('navigation')[0]?.duration || 0
                        })""")
                        filename = os.path.join(EVIDENCE_DIR, f"{browser_name}_{viewport_name}_{_safe_filename(url)}.png")
                        page.screenshot(path=filename, full_page=True)
                        data = {
                            "browser": browser_name, "viewport": viewport_name, "url": url,
                            "status": response.status if response else None,
                            "console_errors": console_errors[:20], "request_failures": request_failures[:20],
                            "horizontal_overflow": metrics["scrollWidth"] > metrics["viewportWidth"] + 2,
                            "scroll_width": metrics["scrollWidth"], "viewport_width": metrics["viewportWidth"],
                            "missing_alt_count": metrics["missingAltCount"], "unlabeled_controls": metrics["unlabeledControls"],
                            "title_present": metrics["titlePresent"], "load_ms": round(metrics["loadTiming"], 1),
                            "screenshot": filename, "headed": headed, "slow_mo_ms": slow_mo,
                        }
                        results.append(data)
                        findings.extend(_page_findings(url, browser_name, viewport_name, data))
                        completed += 1
                        progress = round(completed / total * 100, 1)
                        emit(browser=browser_name.upper(), viewport=viewport_name, pages_tested=len({r["url"] for r in results}),
                             checks=completed, findings=len(findings), errors=sum(len(r["console_errors"])+len(r["request_failures"]) for r in results),
                             progress=progress, stage="CHECK COMPLETE", detail=f"HTTP {data['status']} • {data['load_ms']} ms",
                             matrix_item={"browser": browser_name, "viewport": viewport_name, "url": url, "status": data["status"]},
                             log={"time": "", "level": "ok" if data["status"] and data["status"] < 400 else "warn",
                                  "message": f"Completed {browser_name}/{viewport_name} -> {data['status']}"})
                    except Exception as exc:
                        completed += 1
                        findings.append({
                            "id": f"COMP-PAGE-{abs(hash((browser_name, viewport_name, url))) % 100000:05d}",
                            "title": "Page compatibility check failed", "severity": "Medium", "confidence": "High",
                            "category": "Compatibility", "url": url,
                            "evidence": f"{browser_name}/{viewport_name}: {type(exc).__name__}: {exc}",
                            "detail": "The automated browser could not complete navigation or inspection.",
                            "impact": "The affected browser/viewport combination requires manual investigation.",
                            "remediation": "Reproduce the failure in the specified browser and viewport, then inspect page errors and network requests.",
                        })
                        emit(checks=completed, findings=len(findings), errors=len(findings), progress=round(completed/total*100,1),
                             stage="CHECK FAILED", detail=str(exc),
                             log={"time":"", "level":"err", "message":f"Failed {browser_name}/{viewport_name}: {exc}"})
                    finally:
                        page.close()
                context.close()
            browser.close()

    result = {"target": target, "browsers": list(BROWSERS), "viewports": VIEWPORTS,
              "urls_tested": urls, "results": results, "browser_unavailable": unavailable,
              "findings": findings, "headed": headed, "slow_mo_ms": slow_mo}
    with open(os.path.join(EVIDENCE_DIR, "compatibility.json"), "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, ensure_ascii=False)
    emit(status="COMPLETE", stage="COMPATIBILITY COMPLETE", detail="Browser matrix finished.", progress=100,
         checks=completed, findings=len(findings), finished_at=True,
         log={"time":"", "level":"ok", "message":"Compatibility matrix completed."})
    return result
