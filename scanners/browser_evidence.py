"""Chrome browser evidence capture with focused error-region screenshots."""
import json
import os
import re
from urllib.parse import urlparse

from playwright.sync_api import sync_playwright
from PIL import Image, ImageDraw

from config import EVIDENCE_DIR
from utils.scope import assert_in_scope, assert_same_target


IMAGE_EXTENSIONS = {".png", ".jpg", ".jpeg", ".webp"}


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


def _keywords(finding: dict) -> list[str]:
    """Build conservative, human-readable search tokens from the finding."""
    raw = " ".join(
        str(finding.get(key) or "")
        for key in ("title", "evidence", "detail", "parameter")
    )
    tokens = re.findall(r"[A-Za-z][A-Za-z0-9_-]{3,}", raw.lower())
    stop = {
        "this", "that", "with", "from", "http", "https", "security", "error",
        "failed", "failure", "response", "request", "status", "observed",
        "expected", "finding", "evidence", "parameter", "should", "could",
        "page", "application", "authorized", "authorization",
    }
    result = []
    for token in tokens:
        if token not in stop and token not in result:
            result.append(token)
    # Prefer the first few distinctive tokens; a huge query makes matching noisy.
    return result[:12]


def _find_focus(page, finding: dict) -> dict | None:
    """Locate the actual visible error UI, prioritizing semantic error containers."""
    keywords = _keywords(finding)
    if not keywords:
        return None
    result = page.evaluate(
        """(keywords) => {
            const visible = (el) => {
                const s = getComputedStyle(el);
                const r = el.getBoundingClientRect();
                return s.display !== 'none' && s.visibility !== 'hidden' &&
                       parseFloat(s.opacity || '1') > 0 && r.width >= 8 && r.height >= 8 &&
                       r.bottom >= 0 && r.right >= 0 && r.top <= innerHeight && r.left <= innerWidth;
            };
            const textOf = (el) => (el.innerText || el.textContent || '').trim();
            const errorSelector =
                '[role="alert"],[role="status"],[aria-live="assertive"],[aria-live="polite"],' +
                '.error,.errors,.error-message,.alert,.alert-danger,.alert-error,.danger,' +
                '.invalid,.validation-error,.field-error,.form-error,.toast,.notification,' +
                '.snackbar,.modal,.dialog,[data-error],[data-testid*="error" i],' +
                '[class*="error" i],[id*="error" i],[class*="exception" i],[id*="exception" i]';
            const candidates = [];
            const add = (el, reason, bonus) => {
                if (!visible(el)) return;
                const text = textOf(el);
                if (!text || text.length > 2400) return;
                const lower = text.toLowerCase();
                const hits = keywords.filter(k => lower.includes(k));
                const errorWords = (lower.match(/\b(error|failed|failure|invalid|denied|forbidden|unauthorized|exception|traceback|not found|bad request|server error|access denied)\b/g) || []).length;
                if (!hits.length && !errorWords && bonus < 4) return;
                const r = el.getBoundingClientRect();
                const area = r.width * r.height;
                const viewportArea = innerWidth * innerHeight;
                const giantPenalty = area > viewportArea * 0.72 ? 0.12 : 1;
                const score = bonus * 1000 + Math.min(1, hits.length / Math.max(keywords.length,1)) * 500 +
                    errorWords * 80 + hits.length * 60 - Math.log10(Math.max(area,1)) * 18;
                candidates.push({
                    tag: el.tagName.toLowerCase(), id: el.id || '',
                    className: typeof el.className === 'string' ? el.className.slice(0,220) : '',
                    text: text.slice(0,700), hits, errorWords, reason,
                    x:r.x,y:r.y,width:r.width,height:r.height,score:score*giantPenalty
                });
            };
            for (const el of document.querySelectorAll(errorSelector)) add(el, 'semantic-error-container', 4);
            for (const el of document.querySelectorAll('body *')) {
                if (!visible(el)) continue;
                const text = textOf(el);
                if (!text || text.length > 2400) continue;
                const lower = text.toLowerCase();
                const hits = keywords.filter(k => lower.includes(k));
                const errorWords = (lower.match(/\b(error|failed|failure|invalid|denied|forbidden|unauthorized|exception|traceback|not found|bad request|server error|access denied)\b/g) || []).length;
                if (!hits.length && !errorWords) continue;
                add(el, 'text/error-signal', errorWords ? 2 : 1);
            }
            candidates.sort((a,b) => b.score-a.score);
            const best = candidates.find(x => !['html','body','main'].includes(x.tag) && x.width >= 20 && x.height >= 12) || candidates[0];
            if (!best) return null;
            const target = Array.from(document.querySelectorAll('body *')).find(el =>
                el.tagName.toLowerCase() === best.tag &&
                (best.id ? el.id === best.id : true) &&
                (best.id || (typeof el.className === 'string' && el.className.slice(0,220) === best.className)) &&
                textOf(el).slice(0,700) === best.text
            );
            if (target) {
                document.querySelectorAll('[data-sentinel-focus="1"]').forEach(el =>
                    el.removeAttribute('data-sentinel-focus')
                );
                target.setAttribute('data-sentinel-focus', '1');
                target.scrollIntoView({block:'center', inline:'center', behavior:'instant'});
                const r = target.getBoundingClientRect();
                best.x=r.x; best.y=r.y; best.width=r.width; best.height=r.height;
            }
            return target ? best : null;
        }""",
        keywords,
    )
    if not result or result.get("width",0) < 8 or result.get("height",0) < 8:
        return None
    return result


def _annotate_focus(page, focus: dict, finding_id: str) -> None:
    """Draw a red box, FAILED label and arrow around the detected failure."""
    page.evaluate(
        """({focus, findingId}) => {
            const old = document.getElementById('__sentinel_focus_annotation');
            if (old) old.remove();
            const x=Math.max(4,focus.x), y=Math.max(4,focus.y);
            const w=Math.max(8,Math.min(focus.width,innerWidth-x-4));
            const h=Math.max(8,Math.min(focus.height,innerHeight-y-4));
            const ns='http://www.w3.org/2000/svg';
            const svg=document.createElementNS(ns,'svg');
            svg.id='__sentinel_focus_annotation';
            Object.assign(svg.style,{position:'fixed',left:'0',top:'0',width:'100vw',height:'100vh',zIndex:'2147483646',pointerEvents:'none'});
            svg.setAttribute('viewBox','0 0 '+innerWidth+' '+innerHeight);
            const defs=document.createElementNS(ns,'defs');
            const marker=document.createElementNS(ns,'marker');
            marker.setAttribute('id','sentinel-arrow'); marker.setAttribute('markerWidth','12');
            marker.setAttribute('markerHeight','12'); marker.setAttribute('refX','10');
            marker.setAttribute('refY','4'); marker.setAttribute('orient','auto');
            const arrow=document.createElementNS(ns,'path');
            arrow.setAttribute('d','M0,0 L0,8 L11,4 z'); arrow.setAttribute('fill','#ff1744');
            marker.appendChild(arrow); defs.appendChild(marker); svg.appendChild(defs);
            const rect=document.createElementNS(ns,'rect');
            rect.setAttribute('x',x); rect.setAttribute('y',y); rect.setAttribute('width',w); rect.setAttribute('height',h);
            rect.setAttribute('fill','rgba(255,23,68,.06)'); rect.setAttribute('stroke','#ff1744');
            rect.setAttribute('stroke-width','4'); rect.setAttribute('rx','8'); svg.appendChild(rect);
            const label=document.createElementNS(ns,'text');
            label.setAttribute('x',Math.max(8,Math.min(x,innerWidth-210))); label.setAttribute('y',Math.max(24,y-12));
            label.setAttribute('fill','#ff1744'); label.setAttribute('font-size','16');
            label.setAttribute('font-family','monospace'); label.setAttribute('font-weight','900');
            label.textContent='FAILED: '+findingId; svg.appendChild(label);
            const sx=Math.max(14,Math.min(innerWidth-14,x+w/2));
            const sy=y>95 ? y-65 : Math.min(innerHeight-14,y+h+65);
            const ex=x+w/2, ey=y>95 ? y+4 : y+h-4;
            const line=document.createElementNS(ns,'line');
            line.setAttribute('x1',sx); line.setAttribute('y1',sy); line.setAttribute('x2',ex); line.setAttribute('y2',ey);
            line.setAttribute('stroke','#ff1744'); line.setAttribute('stroke-width','5');
            line.setAttribute('marker-end','url(#sentinel-arrow)'); svg.appendChild(line);
            document.documentElement.appendChild(svg);
        }""",
        {"focus":focus,"findingId":finding_id},
    )


def _focused_screenshot(page, path: str, focus: dict | None) -> dict:
    """Capture ONLY the DOM element that contains the detected error.

    The DOM-element screenshot is the source of truth. Post-capture annotation is
    best-effort and must never downgrade a successful focused capture.
    """
    if not focus:
        return {
            "mode": "no-focused-region",
            "focus_found": False,
            "focus_selector": None,
            "focus_text": None,
            "focus_reason": "No reliable error element was identified; screenshot intentionally skipped.",
        }

    locator = page.locator('[data-sentinel-focus="1"]').first
    try:
        locator.wait_for(state="visible", timeout=3000)
        locator.screenshot(path=path, animations="disabled")
    except Exception as exc:
        return {
            "mode": "focused-element-capture-failed",
            "focus_found": True,
            "focus_selector": {
                "tag": focus.get("tag"),
                "id": focus.get("id"),
                "class": focus.get("className"),
            },
            "focus_text": focus.get("text"),
            "focus_reason": f"Exact error element could not be captured: {type(exc).__name__}: {exc}",
            "error": str(exc),
        }

    annotation_error = None
    try:
        image = Image.open(path).convert("RGB")
        pad_x, pad_y = 12, 28
        canvas = Image.new(
            "RGB",
            (image.width + pad_x * 2, image.height + pad_y * 2),
            "white",
        )
        canvas.paste(image, (pad_x, pad_y))
        draw = ImageDraw.Draw(canvas)
        x1, y1 = pad_x, pad_y
        x2, y2 = pad_x + image.width - 1, pad_y + image.height - 1
        draw.rectangle((x1, y1, x2, y2), outline=(255, 23, 68), width=4)
        label = f"FAILED: {focus.get('finding_id') or 'SECURITY FINDING'}"
        draw.text((pad_x, 5), label, fill=(255, 23, 68))
        arrow_x = max(pad_x + 8, min(x2 - 8, x1 + image.width // 2))
        arrow_y1 = 18
        arrow_y2 = pad_y + min(24, max(8, image.height // 4))
        draw.line(
            (arrow_x, arrow_y1, arrow_x, arrow_y2),
            fill=(255, 23, 68),
            width=4,
        )
        draw.polygon(
            [
                (arrow_x, arrow_y2 + 7),
                (arrow_x - 7, arrow_y2 - 4),
                (arrow_x + 7, arrow_y2 - 4),
            ],
            fill=(255, 23, 68),
        )
        canvas.save(path)
    except Exception as exc:
        # The focused screenshot already exists. Do not convert a successful
        # element capture into a failure merely because PIL annotation failed.
        annotation_error = f"{type(exc).__name__}: {exc}"

    result = {
        "mode": "exact-error-element",
        "focus_found": True,
        "focus_selector": {
            "tag": focus.get("tag"),
            "id": focus.get("id"),
            "class": focus.get("className"),
        },
        "focus_text": focus.get("text"),
        "focus_keywords": focus.get("hits") or [],
        "error_signals": focus.get("errorWords") or 0,
        "focus_reason": "Only the detected error DOM element was captured; no viewport or surrounding webpage was captured.",
        "capture_scope": "single-dom-element",
    }
    if annotation_error:
        result["annotation_warning"] = annotation_error
    return result



def capture_target_overview(target: str, headed: bool = False, slow_mo: int = 0) -> dict:
    """Capture one Chromium viewport of the authorized target homepage for report context."""
    assert_in_scope(target)
    os.makedirs(EVIDENCE_DIR, exist_ok=True)
    path = os.path.join(EVIDENCE_DIR, f"target_overview_{_safe_filename(target)}.png")

    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=not headed, slow_mo=slow_mo)
        context = browser.new_context(viewport={"width": 1440, "height": 900})
        page = context.new_page()
        status = None
        title = ""
        error = None
        try:
            response = page.goto(target, wait_until="domcontentloaded", timeout=30000)
            status = response.status if response else None
            page.wait_for_timeout(750)
            title = page.title()
            page.screenshot(path=path, full_page=False, animations="disabled")
        except Exception as exc:
            error = f"{type(exc).__name__}: {exc}"
        finally:
            page.close()
            context.close()
            browser.close()

    return {
        "target": target,
        "url": target,
        "status": status,
        "title": title,
        "screenshot": path if os.path.isfile(path) else None,
        "capture_scope": "target-viewport-overview",
        "error": error,
    }


def capture_security_evidence(target: str, findings: list[dict], headed: bool = False,
                              slow_mo: int = 0, max_items: int = 30,
                              progress_callback=None, max_seconds: int = 120,
                              navigation_timeout_ms: int = 12000) -> list[dict]:
    """Capture focused visual evidence for active findings using Chromium and GET-only URLs."""
    assert_in_scope(target)
    os.makedirs(EVIDENCE_DIR, exist_ok=True)

    candidates = []
    seen = set()
    priority = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
    ordered_findings = sorted(
        findings,
        key=lambda item: (priority.get(str(item.get("severity") or "Info"), 5),
                          str(item.get("title") or ""), str(item.get("url") or "")),
    )
    for finding in ordered_findings:
        url = finding.get("evidence_url") or finding.get("url")
        if not url or url in seen:
            continue
        try:
            assert_same_target(target, url)
        except Exception:
            continue
        if finding.get("severity") in {"Critical", "High", "Medium"} or finding.get("evidence_url"):
            candidates.append((url, finding.get("id", "security"), finding))
            seen.add(url)
        if len(candidates) >= max_items:
            break

    captured = []
    if not candidates:
        with open(os.path.join(EVIDENCE_DIR, "security_browser_evidence.json"), "w", encoding="utf-8") as f:
            json.dump([], f, indent=2)
        return captured

    started = __import__("time").monotonic()
    total = len(candidates)
    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=not headed, slow_mo=slow_mo)
        context = browser.new_context(viewport={"width": 1440, "height": 900})
        context.set_default_timeout(3500)
        context.set_default_navigation_timeout(navigation_timeout_ms)
        for index, (url, finding_id, finding) in enumerate(candidates, 1):
            elapsed = __import__("time").monotonic() - started
            if elapsed >= max_seconds:
                captured.append({
                    "finding_id": finding_id,
                    "url": url,
                    "status": None,
                    "screenshot": None,
                    "capture": {
                        "mode": "evidence-time-budget-exceeded",
                        "focus_found": False,
                        "focus_reason": f"Evidence phase stopped after the {max_seconds}s safety budget; remaining items were not navigated.",
                    },
                    "console_errors": [],
                    "error": f"EvidencePhaseTimeout: global evidence budget of {max_seconds}s exceeded after {len(captured)} item(s).",
                })
                break

            if progress_callback:
                progress_callback(index - 1, total, finding_id, url, "starting")

            page = context.new_page()
            console_errors = []
            page.on("console", lambda msg: console_errors.append(msg.text) if msg.type == "error" else None)
            screenshot = None
            status = None
            error = None
            focus = None
            capture = {}
            try:
                response = page.goto(url, wait_until="domcontentloaded", timeout=navigation_timeout_ms)
                status = response.status if response else None
                focus = _find_focus(page, finding)
                if focus:
                    focus["finding_id"] = finding_id
                screenshot = os.path.join(
                    EVIDENCE_DIR,
                    f"security_{index:03d}_{_safe_filename(url)}_focused.png",
                )
                capture = _focused_screenshot(page, screenshot, focus)
                if capture.get("mode") == "focused-element-capture-failed":
                    error = capture.get("error") or capture.get("focus_reason")
            except Exception as exc:
                error = f"{type(exc).__name__}: {exc}"
                screenshot = None
                capture = {
                    "mode": "navigation-failure-no-screenshot",
                    "focus_found": False,
                    "focus_reason": f"Navigation failed before an error DOM element could be captured: {type(exc).__name__}: {exc}",
                    "error_type": type(exc).__name__,
                    "error_description": str(exc),
                }
            finally:
                page.close()

            item = {
                "finding_id": finding_id,
                "url": url,
                "status": status,
                "screenshot": screenshot if focus and os.path.isfile(screenshot or "") else None,
                "capture": capture,
                "console_errors": console_errors[:20],
                "error": error,
                "error_type": (type(error).__name__ if error else None),
                "error_description": error,
            }
            captured.append(item)
            if progress_callback:
                progress_callback(index, total, finding_id, url, "completed" if not error else "failed")

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
            finding["evidence_focus"] = item.get("capture", {})

    return captured
