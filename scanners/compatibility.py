"""Chrome-only responsive/UI evidence with marked screenshots and telemetry."""
import json
import os
from urllib.parse import urlparse

from playwright.sync_api import sync_playwright, TimeoutError as PlaywrightTimeoutError

from config import EVIDENCE_DIR
from utils.scope import assert_in_scope, assert_same_target

VIEWPORTS = {
    "mobile-small": {"width": 375, "height": 812},
    "mobile-large": {"width": 390, "height": 844},
    "tablet": {"width": 768, "height": 1024},
    "laptop": {"width": 1366, "height": 768},
    "desktop": {"width": 1440, "height": 900},
    "large-desktop": {"width": 1920, "height": 1080},
}
BROWSERS = ("chromium",)


def _same_target(target: str, url: str) -> bool:
    target_parts = urlparse(target)
    url_parts = urlparse(url)
    return (target_parts.scheme.lower(), target_parts.netloc.lower()) == (url_parts.scheme.lower(), url_parts.netloc.lower())


def _safe_filename(url: str) -> str:
    parsed = urlparse(url)
    value = parsed.netloc + parsed.path + ("_" + parsed.query if parsed.query else "")
    return "".join(ch if ch.isalnum() else "_" for ch in value).strip("_")[:120] or "page"


def _page_findings(url, browser_name, viewport_name, data):
    findings = []
    prefix = f"{browser_name}/{viewport_name}"
    screenshot = data.get("screenshot")
    for error in data["console_errors"]:
        findings.append({
            "id": f"COMP-CONSOLE-{abs(hash((url, prefix, error))) % 100000:05d}",
            "title": "Browser console error", "severity": "Low", "confidence": "High",
            "category": "Compatibility", "method": "GET", "url": url,
            "evidence": f"{prefix}: {error}", "screenshot": screenshot,
            "detail": "The page emitted a browser console error during automated navigation.",
            "impact": "Console errors can indicate broken JavaScript, failed integrations, or client-side functionality that may not work correctly for users.",
            "remediation": "Inspect the originating JavaScript error and fix the failing client-side code or dependency.",
        })
    if data.get("status") is not None and data["status"] >= 400:
        findings.append({
            "id": f"COMP-HTTP-{abs(hash((url, prefix, data['status']))) % 100000:05d}",
            "title": "HTTP page failure status",
            "severity": "Medium",
            "confidence": "High",
            "category": "Compatibility",
            "method": "GET",
            "url": url,
            "evidence": f"{prefix}: HTTP {data['status']}",
            "screenshot": screenshot,
            "detail": "Chrome received an HTTP error status for the requested page.",
            "impact": "Users may be unable to load the affected page or workflow.",
            "remediation": "Inspect the server response, routing, deployment configuration, and application logs for the affected URL.",
        })
    for failure in data["request_failures"]:
        findings.append({
            "id": f"COMP-NET-{abs(hash((url, prefix, failure))) % 100000:05d}",
            "title": "Failed browser network request", "severity": "Medium", "confidence": "High",
            "category": "Compatibility", "method": "GET", "url": url,
            "evidence": f"{prefix}: {failure}", "screenshot": screenshot,
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
            "screenshot": screenshot,
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
            "screenshot": screenshot,
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
            "screenshot": screenshot,
            "detail": "Automated markup inspection found controls without an obvious associated label.",
            "impact": "Users of assistive technology may have difficulty identifying the purpose of controls.",
            "remediation": "Associate each control with a visible label or an appropriate accessible name.",
        })
    return findings


def _mark_evidence(page, issues):
    """Add a non-destructive visual evidence marker before the final screenshot."""
    if not issues:
        return
    labels = " | ".join(issues[:6])
    page.evaluate(
        """(label) => {
            const old = document.getElementById('__sentinel_evidence_marker');
            if (old) old.remove();
            const box = document.createElement('div');
            box.id = '__sentinel_evidence_marker';
            box.textContent = 'SENTINEL // EVIDENCE MARKER — ' + label;
            Object.assign(box.style, {
                position:'fixed', top:'12px', left:'12px', zIndex:'2147483647',
                maxWidth:'calc(100vw - 24px)', padding:'10px 14px',
                background:'#8b0000', color:'#fff', border:'2px solid #ff4040',
                borderRadius:'6px', font:'700 13px/1.3 monospace',
                boxShadow:'0 4px 18px rgba(0,0,0,.45)'
            });
            document.documentElement.appendChild(box);
        }""",
        labels,
    )


def run_compatibility(target: str, urls: list[str], max_pages: int = 12,
                      headed: bool = False, slow_mo: int = 0, telemetry=None) -> dict:
    assert_in_scope(target)
    os.makedirs(EVIDENCE_DIR, exist_ok=True)
    assert_same_target(target, target)
    urls = [u for u in list(dict.fromkeys(urls)) if _same_target(target, u)][:max_pages]
    results, findings, unavailable = [], [], []
    total = max(1, len(urls) * len(BROWSERS) * len(VIEWPORTS))
    completed = 0

    def emit(**payload):
        if telemetry:
            telemetry(**payload)

    emit(stage="BROWSER ENGINE INITIALIZATION", detail="Preparing Chrome/Chromium browser matrix.", progress=0,
         log={"time": "00:00", "level": "ok", "message": "Chrome-only compatibility engine initialized."})

    with sync_playwright() as pw:
        for browser_name in BROWSERS:
            emit(browser="CHROME", stage="CHROME ENGINE",
                 detail="Launching Chromium.")
            try:
                browser = pw.chromium.launch(headless=not headed, slow_mo=slow_mo)
            except Exception as exc:
                unavailable.append({"browser": browser_name, "reason": str(exc)})
                emit(stage="CHROME UNAVAILABLE", detail=str(exc),
                     log={"time": "", "level": "warn", "message": f"Chrome/Chromium unavailable: {exc}"})
                continue

            for viewport_name, viewport in VIEWPORTS.items():
                context = browser.new_context(viewport=viewport)
                for url in urls:
                    assert_same_target(target, url)
                    page = context.new_page()
                    console_errors, request_failures = [], []
                    page.on("console", lambda msg: console_errors.append(msg.text) if msg.type == "error" else None)
                    page.on("requestfailed", lambda req: request_failures.append(f"{req.method} {req.url}: {req.failure}"))
                    emit(browser="CHROME", viewport=viewport_name,
                         stage="NAVIGATING", detail=url,
                         log={"time": "", "level": "", "message": f"[CHROME/{viewport_name}] {url}"})
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

                        issues = []
                        if console_errors:
                            issues.append(f"CONSOLE ERRORS: {len(console_errors)}")
                        if request_failures:
                            issues.append(f"NETWORK FAILURES: {len(request_failures)}")
                        overflow = metrics["scrollWidth"] > metrics["viewportWidth"] + 2
                        if overflow:
                            issues.append(f"HORIZONTAL OVERFLOW: {metrics['scrollWidth']}px > {metrics['viewportWidth']}px")
                        if metrics["missingAltCount"]:
                            issues.append(f"MISSING ALT: {metrics['missingAltCount']}")
                        if metrics["unlabeledControls"]:
                            issues.append(f"UNLABELED CONTROLS: {metrics['unlabeledControls']}")

                        if response and response.status >= 400:
                            issues.append(f"HTTP FAILURE: {response.status}")

                        evidence_marked = bool(issues)
                        if evidence_marked:
                            _mark_evidence(page, issues)

                        filename = os.path.join(
                            EVIDENCE_DIR,
                            f"chromium_{viewport_name}_{_safe_filename(url)}.png"
                        )
                        page.screenshot(path=filename, full_page=True)
                        data = {
                            "browser": "chromium", "viewport": viewport_name, "url": url,
                            "status": response.status if response else None,
                            "console_errors": console_errors[:20], "request_failures": request_failures[:20],
                            "horizontal_overflow": overflow,
                            "scroll_width": metrics["scrollWidth"], "viewport_width": metrics["viewportWidth"],
                            "missing_alt_count": metrics["missingAltCount"], "unlabeled_controls": metrics["unlabeledControls"],
                            "title_present": metrics["titlePresent"], "load_ms": round(metrics["loadTiming"], 1),
                            "screenshot": filename, "evidence_marked": evidence_marked,
                            "issues_marked": issues, "headed": headed, "slow_mo_ms": slow_mo,
                        }
                        results.append(data)
                        findings.extend(_page_findings(url, "chromium", viewport_name, data))
                        completed += 1
                        progress = round(completed / total * 100, 1)
                        emit(browser="CHROME", viewport=viewport_name, pages_tested=len({r["url"] for r in results}),
                             checks=completed, findings=len(findings),
                             errors=sum(len(r["console_errors"])+len(r["request_failures"]) for r in results),
                             progress=progress, stage="CHECK COMPLETE",
                             detail=f"HTTP {data['status']} • {data['load_ms']} ms",
                             matrix_item={"browser":"chromium","viewport":viewport_name,"url":url,"status":data["status"]},
                             log={"time":"","level":"ok" if data["status"] and data["status"] < 400 else "warn",
                                  "message":f"Completed CHROME/{viewport_name} -> {data['status']}"})
                    except Exception as exc:
                        completed += 1
                        finding_key = ("chromium", viewport_name, url)
                        failure_label = f"CHROME/{viewport_name} navigation or inspection failure"
                        failure_issues = [f"CHECK FAILED: {type(exc).__name__}", str(exc)]
                        try:
                            _mark_evidence(page, failure_issues)
                            failure_filename = os.path.join(
                                EVIDENCE_DIR,
                                f"chromium_failure_{viewport_name}_{_safe_filename(url)}.png"
                            )
                            page.screenshot(path=failure_filename, full_page=True)
                        except Exception as screenshot_exc:
                            failure_filename = None
                            failure_issues.append(f"SCREENSHOT FAILED: {type(screenshot_exc).__name__}: {screenshot_exc}")

                        findings.append({
                            "id": f"COMP-PAGE-{abs(hash(finding_key)) % 100000:05d}",
                            "title": "Page compatibility check failed", "severity": "Medium", "confidence": "High",
                            "category": "Compatibility", "url": url,
                            "evidence": f"chromium/{viewport_name}: {type(exc).__name__}: {exc}",
                            "screenshot": failure_filename,
                            "detail": "The Chrome browser could not complete navigation or inspection. A marked failure screenshot is captured when Playwright can still render the page.",
                            "impact": "The affected viewport requires manual investigation and may represent a broken user experience.",
                            "remediation": "Reproduce the failure in Chrome at the specified viewport and inspect page errors and network requests.",
                        })
                        emit(checks=completed, findings=len(findings), errors=len(findings),
                             progress=round(completed/total*100,1), stage="CHECK FAILED", detail=str(exc),
                             log={"time":"","level":"err","message":failure_label})
                    finally:
                        page.close()
                context.close()
            browser.close()

    result = {
        "target": target, "browsers": ["chromium"], "viewports": VIEWPORTS,
        "urls_tested": urls, "results": results, "browser_unavailable": unavailable,
        "findings": findings, "headed": headed, "slow_mo_ms": slow_mo,
    }
    with open(os.path.join(EVIDENCE_DIR, "compatibility.json"), "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, ensure_ascii=False)
    emit(status="COMPLETE", stage="COMPATIBILITY COMPLETE", detail="Chrome-only responsive matrix finished.",
         progress=100, checks=completed, findings=len(findings), finished_at=True,
         log={"time":"","level":"ok","message":"Chrome-only compatibility matrix completed."})
    return result
