"""Chrome-only responsive/UI checks with focused failure evidence.

Evidence policy:
- PASSING checks do not create screenshots.
- FAILED checks capture only the DOM element responsible for the failure.
- Responsive overflow captures the offending element, not the full page.
- Missing-alt checks capture the offending image only.
- Unlabelled-control checks capture the offending control only.
- Console/network failures capture a visible error element when one exists.
- If no reliable failure element can be identified, no screenshot is created.
"""

import json
import os
from pathlib import Path
from urllib.parse import urlparse

from PIL import Image, ImageDraw, ImageFont
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
    return (
        target_parts.scheme.lower(),
        target_parts.netloc.lower(),
    ) == (
        url_parts.scheme.lower(),
        url_parts.netloc.lower(),
    )


def _safe_filename(url: str) -> str:
    parsed = urlparse(url)
    value = parsed.netloc + parsed.path + (
        "_" + parsed.query if parsed.query else ""
    )
    return "".join(
        ch if ch.isalnum() else "_" for ch in value
    ).strip("_")[:120] or "page"


def _request_failure_is_actionable(failure: str, page_url: str) -> bool:
    """Ignore browser cancellations and noisy third-party telemetry failures."""
    value = str(failure or "")
    lower = value.lower()
    if any(token in lower for token in (
        "err_aborted", "err_blocked_by_client", "err_canceled",
        "net::err_aborted", "net::err_blocked_by_client",
    )):
        return False
    try:
        from urllib.parse import urlparse
        request_url = value.split(" ", 2)[1].split(":", 1)[0] if value.split(" ", 2) else ""
        # Extract the URL from strings like "POST https://host/path: net::ERR_*".
        if "://" in value:
            request_url = value[value.find("://") - (value[:value.find("://")].rfind(" ") + 1):].split(" ", 1)[0]
            request_url = request_url.rstrip(":")
        page_host = (urlparse(page_url).hostname or "").lower()
        request_host = (urlparse(request_url).hostname or "").lower()
    except Exception:
        page_host, request_host = "", ""
    # A failed analytics/advertising beacon is not evidence that the target app is broken.
    telemetry_hosts = (
        "google-analytics.com", "googletagmanager.com", "google.com",
        "doubleclick.net", "googlesyndication.com", "facebook.net",
        "facebook.com", "hotjar.com", "clarity.ms", "segment.io",
        "segment.com", "mixpanel.com", "amplitude.com",
    )
    if request_host and any(
        request_host == host or request_host.endswith("." + host)
        for host in telemetry_hosts
    ):
        return False
    # Keep first-party failures and other actionable resources. Third-party
    # failures may still matter when they are not known telemetry.
    return True


def _page_findings(url, browser_name, viewport_name, data):
    """Create findings and attach only the focused evidence for each failed case."""
    findings = []
    prefix = f"{browser_name}/{viewport_name}"

    def evidence_path(kind):
        item = data.get("focused_evidence", {}).get(kind)
        return item.get("path") if item else None

    for error in data["console_errors"]:
        findings.append({
            "id": f"COMP-CONSOLE-{abs(hash((url, error))) % 100000:05d}",
            "title": "Browser console error",
            "severity": "Low",
            "confidence": "High",
            "category": "Compatibility",
            "method": "GET",
            "url": url,
            "evidence": f"{prefix}: {error}",
            "screenshot": evidence_path("console"),
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
            "screenshot": evidence_path("http"),
            "detail": "Chrome received an HTTP error status for the requested page.",
            "impact": "Users may be unable to load the affected page or workflow.",
            "remediation": "Inspect the server response, routing, deployment configuration, and application logs for the affected URL.",
        })

    for failure in data["request_failures"]:
        if not _request_failure_is_actionable(failure, url):
            continue
        findings.append({
            "id": f"COMP-NET-{abs(hash((url, failure))) % 100000:05d}",
            "title": "Failed browser network request",
            "severity": "Medium",
            "confidence": "Medium",
            "category": "Compatibility / Network",
            "method": failure.split(" ", 1)[0] if " " in failure else "GET",
            "url": url,
            "evidence": f"Page: {url}\\nFailed request: {failure}\\nViewport: {viewport_name}\\nBrowser: {browser_name}",
            "screenshot": evidence_path("network"),
            "detail": "A browser request failed during page load. This finding is limited to a reproducible, non-telemetry request; browser cancellations and common analytics beacons are excluded.",
            "impact": "If the failed request belongs to the application, its script, stylesheet, image, or API response may be unavailable. The actual user impact depends on whether the resource is required for the affected workflow.",
            "remediation": "Open the exact failed request in the browser Network panel; verify DNS/TLS, response status, CORS headers, authentication, cache/CDN behavior, and server logs. Fix the underlying request only after confirming that it is first-party or required by the application.",
        })

    if data["horizontal_overflow"]:
        findings.append({
            "id": f"COMP-OVERFLOW-{abs(hash((url, viewport_name))) % 100000:05d}",
            "title": "Horizontal overflow at responsive viewport",
            "severity": "Medium",
            "confidence": "High",
            "category": "Responsive UI",
            "method": "GET",
            "url": url,
            "evidence": f"{prefix}: document scrollWidth={data['scroll_width']} viewportWidth={data['viewport_width']}",
            "screenshot": evidence_path("overflow"),
            "detail": "The document is wider than the viewport and the evidence image identifies the offending element.",
            "impact": "Horizontal overflow can hide content or make mobile and narrow-screen interfaces difficult to use.",
            "remediation": "Inspect the highlighted element for fixed widths, oversized media, long unbroken content, positioned elements, and container overflow rules.",
        })

    if data["missing_alt_count"]:
        findings.append({
            "id": f"COMP-ALT-{abs(hash((url, data['missing_alt_count']))) % 100000:05d}",
            "title": "Images missing alternative text",
            "severity": "Low",
            "confidence": "High",
            "category": "Accessibility",
            "cwe": "CWE-116",
            "url": url,
            "evidence": f"{data['missing_alt_count']} image element(s) without an alt attribute.",
            "screenshot": evidence_path("alt"),
            "detail": "The evidence image contains the affected image element only.",
            "impact": "Important visual information may not be available to users relying on assistive technology.",
            "remediation": "Provide meaningful alt text for informative images and an empty alt attribute for purely decorative images.",
        })

    if data["unlabeled_controls"]:
        findings.append({
            "id": f"COMP-LABEL-{abs(hash((url, data['unlabeled_controls']))) % 100000:05d}",
            "title": "Potentially unlabeled form controls",
            "severity": "Low",
            "confidence": "Medium",
            "category": "Accessibility",
            "url": url,
            "evidence": f"{data['unlabeled_controls']} form control(s) could not be associated with a label.",
            "screenshot": evidence_path("control"),
            "detail": "The evidence image contains the affected control only.",
            "impact": "Users of assistive technology may have difficulty identifying the purpose of controls.",
            "remediation": "Associate each control with a visible label or an appropriate accessible name.",
        })

    return findings


def _focus_failure_element(page, failure_types):
    """Find the smallest visible DOM element responsible for a failed check.

    The function deliberately avoids html/body/main and rejects giant containers.
    It returns a Playwright locator plus diagnostic metadata.
    """
    result = page.evaluate(
        """(failureTypes) => {
            const visible = (el) => {
                const s = getComputedStyle(el);
                const r = el.getBoundingClientRect();
                return s.display !== 'none' &&
                       s.visibility !== 'hidden' &&
                       Number.parseFloat(s.opacity || '1') > 0 &&
                       r.width >= 8 && r.height >= 8 &&
                       r.bottom >= 0 && r.right >= 0 &&
                       r.top <= innerHeight && r.left <= innerWidth;
            };

            const text = (el) => (el.innerText || el.textContent || '').trim();

            const candidates = [];
            const add = (el, kind, scoreBonus) => {
                if (!visible(el)) return;
                const r = el.getBoundingClientRect();
                const area = Math.max(1, r.width * r.height);
                const viewportArea = Math.max(1, innerWidth * innerHeight);
                if (area > viewportArea * 0.70) return;

                const tag = el.tagName.toLowerCase();
                if (['html', 'body', 'main'].includes(tag)) return;

                let score = scoreBonus;
                if (failureTypes.includes('overflow')) {
                    const rightOverflow = Math.max(0, r.right - innerWidth);
                    const leftOverflow = Math.max(0, -r.left);
                    if (rightOverflow <= 0 && leftOverflow <= 0) return;
                    score += Math.max(rightOverflow, leftOverflow) * 10;
                }

                if (failureTypes.includes('alt')) {
                    if (tag !== 'img' || el.hasAttribute('alt')) return;
                    score += 1000;
                }

                if (failureTypes.includes('control')) {
                    if (!['input','select','textarea','button'].includes(tag)) return;
                    if (tag === 'input' && ['hidden','submit','button','reset','image'].includes(el.type)) return;
                    if (el.labels && el.labels.length) return;
                    if (el.getAttribute('aria-label') || el.getAttribute('aria-labelledby') || el.title) return;
                    score += 1000;
                }

                if (failureTypes.includes('error') || failureTypes.includes('http') || failureTypes.includes('network') || failureTypes.includes('console')) {
                    const lower = text(el).toLowerCase();
                    const errorWords = (lower.match(/\b(error|failed|failure|invalid|denied|forbidden|unauthorized|exception|traceback|not found|bad request|server error|access denied|unable|cannot)\b/g) || []).length;
                    if (!errorWords && !el.matches('[role="alert"],[role="status"],[aria-live="assertive"],[aria-live="polite"],[class*="error" i],[id*="error" i],[class*="alert" i],[id*="alert" i],[class*="exception" i],[id*="exception" i]')) return;
                    score += errorWords * 200;
                }

                // Smaller elements are preferred so evidence stays focused.
                score += 250 / Math.max(1, Math.log10(area));
                candidates.push({
                    tag, id: el.id || '',
                    className: typeof el.className === 'string' ? el.className.slice(0, 220) : '',
                    text: text(el).slice(0, 700),
                    x: r.x, y: r.y, width: r.width, height: r.height,
                    kind, score
                });
            };

            const selectors = [
                '[role="alert"]','[role="status"]','[aria-live="assertive"]','[aria-live="polite"]',
                '.error','.errors','.error-message','.alert','.alert-danger','.alert-error',
                '.invalid','.validation-error','.field-error','.form-error','.toast',
                '.notification','.snackbar','.modal','.dialog',
                '[data-error]','[data-testid*="error" i]',
                '[class*="error" i]','[id*="error" i]',
                '[class*="exception" i]','[id*="exception" i]'
            ].join(',');

            if (failureTypes.some(x => ['error','http','network','console'].includes(x))) {
                document.querySelectorAll(selectors).forEach(el => add(el, 'error-ui', 900));
            }

            if (failureTypes.includes('overflow')) {
                document.querySelectorAll('body *').forEach(el => add(el, 'overflow', 800));
            }

            if (failureTypes.includes('alt')) {
                document.querySelectorAll('img').forEach(el => add(el, 'missing-alt', 1000));
            }

            if (failureTypes.includes('control')) {
                document.querySelectorAll('input,select,textarea,button').forEach(el => add(el, 'unlabeled-control', 1000));
            }

            candidates.sort((a,b) => b.score - a.score);
            const best = candidates[0];
            if (!best) return null;

            const nodes = Array.from(document.querySelectorAll('body *'));
            const target = nodes.find(el =>
                el.tagName.toLowerCase() === best.tag &&
                (best.id ? el.id === best.id : true) &&
                (!best.id ? (typeof el.className === 'string' && el.className.slice(0,220) === best.className) : true) &&
                (el.innerText || el.textContent || '').trim().slice(0,700) === best.text
            );

            if (!target) return null;

            document.querySelectorAll('[data-sentinel-focus="1"]').forEach(el => el.removeAttribute('data-sentinel-focus'));
            target.setAttribute('data-sentinel-focus', '1');
            target.scrollIntoView({block:'center', inline:'center', behavior:'instant'});

            const r = target.getBoundingClientRect();
            return {
                ...best,
                x:r.x, y:r.y, width:r.width, height:r.height,
                selector:'[data-sentinel-focus="1"]'
            };
        }""",
        failure_types,
    )
    return result


def _annotate_image(path: str, finding_id: str) -> None:
    """Annotate an already isolated element image without adding anything to the target page."""
    image = Image.open(path).convert("RGB")
    top = 42
    side = 14
    bottom = 14
    canvas = Image.new(
        "RGB",
        (image.width + side * 2, image.height + top + bottom),
        "white",
    )
    canvas.paste(image, (side, top))
    draw = ImageDraw.Draw(canvas)

    try:
        font = ImageFont.truetype("DejaVuSans-Bold.ttf", 18)
    except Exception:
        font = ImageFont.load_default()

    label = f"FAILED: {finding_id}"
    draw.text((side, 10), label, fill=(220, 0, 35), font=font)

    x1, y1 = side, top
    x2, y2 = side + image.width - 1, top + image.height - 1
    draw.rectangle((x1, y1, x2, y2), outline=(220, 0, 35), width=4)

    arrow_x = max(x1 + 8, min(x2 - 8, x1 + image.width // 2))
    arrow_start = 31
    arrow_end = top + min(24, max(8, image.height // 3))
    draw.line((arrow_x, arrow_start, arrow_x, arrow_end), fill=(220, 0, 35), width=4)
    draw.polygon(
        [
            (arrow_x, arrow_end + 7),
            (arrow_x - 7, arrow_end - 4),
            (arrow_x + 7, arrow_end - 4),
        ],
        fill=(220, 0, 35),
    )

    canvas.save(path)


def _capture_focused_failure(page, finding_id: str, path: str, failure_types):
    """Capture only the failed DOM element. Never fall back to viewport/full-page capture."""
    focus = _focus_failure_element(page, failure_types)
    if not focus:
        return {
            "path": None,
            "mode": "no-focused-region",
            "focus_found": False,
            "reason": "No reliable issue-specific DOM element was identified; screenshot skipped.",
        }

    locator = page.locator('[data-sentinel-focus="1"]').first
    try:
        locator.wait_for(state="visible", timeout=3000)
        locator.screenshot(path=path, animations="disabled")
        _annotate_image(path, finding_id)
        return {
            "path": path,
            "mode": "exact-failed-element",
            "focus_found": True,
            "capture_scope": "single-dom-element",
            "element": focus,
            "reason": "Only the DOM element responsible for the failed check was captured.",
        }
    except Exception as exc:
        try:
            if Path(path).exists():
                Path(path).unlink()
        except OSError:
            pass
        return {
            "path": None,
            "mode": "focused-capture-failed",
            "focus_found": True,
            "capture_scope": "single-dom-element",
            "element": focus,
            "reason": f"Focused element screenshot failed: {type(exc).__name__}: {exc}",
        }


def _failure_types_for_case(data):
    """Map each failed responsive check to the DOM element type that can prove it."""
    kinds = []
    if data.get("horizontal_overflow"):
        kinds.append("overflow")
    if data.get("missing_alt_count"):
        kinds.append("alt")
    if data.get("unlabeled_controls"):
        kinds.append("control")
    if data.get("status") is not None and data["status"] >= 400:
        kinds.append("http")
    if data.get("request_failures"):
        kinds.append("network")
    if data.get("console_errors"):
        kinds.append("console")
    return kinds


def _capture_case_evidence(page, url, viewport_name, issues, data):
    """Capture one focused image per failed case for the current responsive viewport."""
    if not issues:
        return {}

    results = {}
    types = _failure_types_for_case(data)
    if not types:
        return results

    for kind in dict.fromkeys(types):
        finding_id = f"COMP-{kind.upper()}-{abs(hash((url, viewport_name, kind))) % 100000:05d}"
        path = os.path.join(
            EVIDENCE_DIR,
            f"chromium_{viewport_name}_{_safe_filename(url)}_{kind}_focused.png",
        )
        capture = _capture_focused_failure(page, finding_id, path, [kind])
        results[kind] = capture
    return results


def run_compatibility(target: str, urls: list[str], max_pages: int = 12,
                      headed: bool = False, slow_mo: int = 0, telemetry=None) -> dict:
    assert_in_scope(target)
    os.makedirs(EVIDENCE_DIR, exist_ok=True)
    assert_same_target(target, target)
    urls = [u for u in list(dict.fromkeys(urls)) if _same_target(target, u)][:max_pages]
    results, findings, unavailable = [], [], []
    # Test all six viewport sizes on the first three representative pages, then
    # keep mobile + laptop coverage on every remaining discovered page. This
    # avoids multiplying every slow third-party asset load by six.
    representative_urls = set(urls[:3])
    total_cases = sum(
        len(VIEWPORTS) if url in representative_urls else 2
        for url in urls
    )
    total = max(1, total_cases * len(BROWSERS))
    completed = 0

    def emit(**payload):
        if telemetry:
            telemetry(**payload)

    emit(
        stage="BROWSER ENGINE INITIALIZATION",
        detail="Preparing Chrome/Chromium browser matrix.",
        progress=0,
        log={"time": "00:00", "level": "ok", "message": "Chrome-only compatibility engine initialized."},
    )

    with sync_playwright() as pw:
        for browser_name in BROWSERS:
            emit(browser="CHROME", stage="CHROME ENGINE", detail="Launching Chromium.")
            try:
                browser = pw.chromium.launch(headless=not headed, slow_mo=slow_mo)
            except Exception as exc:
                unavailable.append({"browser": browser_name, "reason": str(exc)})
                emit(
                    stage="CHROME UNAVAILABLE",
                    detail=str(exc),
                    log={"time": "", "level": "warn", "message": f"Chrome/Chromium unavailable: {exc}"},
                )
                continue

            for viewport_name, viewport in VIEWPORTS.items():
                # Keep full matrix for representative routes; every discovered
                # URL still receives mobile-small and laptop checks.
                if viewport_name not in {"mobile-small", "laptop"}:
                    viewport_urls = urls[:3]
                else:
                    viewport_urls = urls
                context = browser.new_context(viewport=viewport)
                for url in viewport_urls:
                    assert_same_target(target, url)
                    page = context.new_page()
                    console_errors, request_failures = [], []

                    page.on(
                        "console",
                        lambda msg: console_errors.append(msg.text) if msg.type == "error" else None,
                    )
                    page.on(
                        "requestfailed",
                        lambda req: request_failures.append(
                            f"{req.method} {req.url}: {req.failure}"
                        ),
                    )

                    emit(
                        browser="CHROME",
                        viewport=viewport_name,
                        stage="NAVIGATING",
                        detail=url,
                        log={"time": "", "level": "", "message": f"[CHROME/{viewport_name}] {url}"},
                    )

                    try:
                        response = page.goto(
                            url,
                            wait_until="domcontentloaded",
                            timeout=12000,
                        )
                        # DOMContentLoaded is enough for layout/DOM checks. Waiting
                        # for networkidle made sites with analytics and streaming
                        # assets spend five extra seconds on every viewport.

                        metrics = page.evaluate(
                            """() => ({
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
                            })"""
                        )

                        issues = []
                        if console_errors:
                            issues.append(f"CONSOLE ERRORS: {len(console_errors)}")
                        if request_failures:
                            issues.append(f"NETWORK FAILURES: {len(request_failures)}")

                        overflow = metrics["scrollWidth"] > metrics["viewportWidth"] + 2
                        if overflow:
                            issues.append(
                                f"HORIZONTAL OVERFLOW: {metrics['scrollWidth']}px > "
                                f"{metrics['viewportWidth']}px"
                            )

                        if metrics["missingAltCount"]:
                            issues.append(f"MISSING ALT: {metrics['missingAltCount']}")
                        if metrics["unlabeledControls"]:
                            issues.append(f"UNLABELED CONTROLS: {metrics['unlabeledControls']}")
                        if response and response.status >= 400:
                            issues.append(f"HTTP FAILURE: {response.status}")

                        data = {
                            "browser": "chromium",
                            "viewport": viewport_name,
                            "url": url,
                            "status": response.status if response else None,
                            "console_errors": console_errors[:20],
                            "request_failures": request_failures[:20],
                            "horizontal_overflow": overflow,
                            "scroll_width": metrics["scrollWidth"],
                            "viewport_width": metrics["viewportWidth"],
                            "missing_alt_count": metrics["missingAltCount"],
                            "unlabeled_controls": metrics["unlabeledControls"],
                            "title_present": metrics["titlePresent"],
                            "load_ms": round(metrics["loadTiming"], 1),
                            "screenshot": None,
                            "evidence_marked": bool(issues),
                            "issues_marked": issues,
                            "headed": headed,
                            "slow_mo_ms": slow_mo,
                            "focused_evidence": {},
                        }

                        # Critical rule: screenshots exist only for failed cases,
                        # and every screenshot is limited to the responsible DOM element.
                        if issues:
                            data["focused_evidence"] = _capture_case_evidence(
                                page, url, viewport_name, issues, data
                            )

                        results.append(data)
                        findings.extend(
                            _page_findings(url, "chromium", viewport_name, data)
                        )

                        completed += 1
                        progress = round(completed / total * 100, 1)
                        emit(
                            browser="CHROME",
                            viewport=viewport_name,
                            pages_tested=len({r["url"] for r in results}),
                            checks=completed,
                            findings=len(findings),
                            errors=len({
                                (r["url"], "console", error)
                                for r in results for error in r["console_errors"]
                            } | {
                                (r["url"], "network", failure)
                                for r in results for failure in r["request_failures"]
                                if "ERR_ABORTED" not in failure and "ERR_BLOCKED_BY_CLIENT" not in failure
                            }),
                            progress=progress,
                            stage="CHECK COMPLETE",
                            detail=f"HTTP {data['status']} • {data['load_ms']} ms",
                            matrix_item={
                                "browser": "chromium",
                                "viewport": viewport_name,
                                "url": url,
                                "status": data["status"],
                            },
                            log={
                                "time": "",
                                "level": "ok" if data["status"] and data["status"] < 400 else "warn",
                                "message": f"Completed CHROME/{viewport_name} -> {data['status']}",
                            },
                        )

                    except Exception as exc:
                        completed += 1
                        finding_key = ("chromium", viewport_name, url)
                        failure_label = (
                            f"CHROME/{viewport_name} navigation or inspection failure"
                        )
                        failure_issues = [
                            f"CHECK FAILED: {type(exc).__name__}",
                            str(exc),
                        ]

                        # Even an exception path is fail-closed: try to identify
                        # a visible error element, but never capture the viewport.
                        failure_data = {
                            "status": response.status if "response" in locals() and response else None,
                            "console_errors": console_errors,
                            "request_failures": request_failures,
                            "horizontal_overflow": False,
                            "missing_alt_count": 0,
                            "unlabeled_controls": 0,
                        }
                        focus = _capture_focused_failure(
                            page,
                            f"COMP-PAGE-{abs(hash(finding_key)) % 100000:05d}",
                            os.path.join(
                                EVIDENCE_DIR,
                                f"chromium_failure_{viewport_name}_{_safe_filename(url)}_focused.png",
                            ),
                            ["error"],
                        )

                        findings.append({
                            "id": f"COMP-PAGE-{abs(hash(finding_key)) % 100000:05d}",
                            "title": "Page compatibility check failed",
                            "severity": "Medium",
                            "confidence": "High",
                            "category": "Compatibility",
                            "url": url,
                            "evidence": f"chromium/{viewport_name}: {type(exc).__name__}: {exc}",
                            "screenshot": focus.get("path"),
                            "evidence_capture": focus,
                            "detail": "Chrome could not complete navigation or inspection. A screenshot is retained only when a specific visible failure element can be isolated.",
                            "impact": "The affected viewport requires manual investigation and may represent a broken user experience.",
                            "remediation": "Reproduce the failure in Chrome at the specified viewport and inspect page errors and network requests.",
                        })

                        emit(
                            checks=completed,
                            findings=len(findings),
                            errors=len(findings),
                            progress=round(completed / total * 100, 1),
                            stage="CHECK FAILED",
                            detail=str(exc),
                            log={"time": "", "level": "err", "message": failure_label},
                        )
                    finally:
                        page.close()

                context.close()
            browser.close()

    result = {
        "target": target,
        "browsers": ["chromium"],
        "viewports": VIEWPORTS,
        "urls_tested": urls,
        "results": results,
        "browser_unavailable": unavailable,
        "findings": findings,
        "headed": headed,
        "slow_mo_ms": slow_mo,
        "evidence_policy": {
            "passing_screenshots": False,
            "failed_case_screenshots": True,
            "capture_scope": "single-dom-element",
            "full_page_fallback": False,
            "viewport_fallback": False,
        },
    }

    with open(
        os.path.join(EVIDENCE_DIR, "compatibility.json"),
        "w",
        encoding="utf-8",
    ) as f:
        json.dump(result, f, indent=2, ensure_ascii=False)

    emit(
        status="COMPLETE",
        stage="COMPATIBILITY COMPLETE",
        detail="Chrome-only responsive matrix finished.",
        progress=100,
        checks=completed,
        findings=len(findings),
        finished_at=True,
        log={"time": "", "level": "ok", "message": "Chrome-only compatibility matrix completed."},
    )
    return result
