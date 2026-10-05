"""Chrome browser evidence capture with focused error-region screenshots."""
import json
import os
import re
from urllib.parse import urlparse

from playwright.sync_api import sync_playwright

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
                target.scrollIntoView({block:'center', inline:'center', behavior:'instant'});
                const r = target.getBoundingClientRect();
                best.x=r.x; best.y=r.y; best.width=r.width; best.height=r.height;
            }
            return best;
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
    """Capture only the detected error region; never fall back to a viewport screenshot."""
    if not focus:
        return {
            "mode": "no-focused-region",
            "focus_found": False,
            "focus_selector": None,
            "focus_text": None,
            "focus_reason": (
                "No reliable error UI was identified; screenshot intentionally skipped "
                "to prevent full-page or viewport evidence."
            ),
        }

    viewport = page.viewport_size or {"width": 1440, "height": 900}
    # Keep the evidence deliberately tight: only the error element plus a small context margin.
    margin_x, margin_y = 18, 24
    max_width, max_height = min(760, viewport["width"]), min(520, viewport["height"])
    cx = focus["x"] + focus["width"] / 2
    cy = focus["y"] + focus["height"] / 2
    width = min(max_width, max(220, focus["width"] + margin_x * 2))
    height = min(max_height, max(120, focus["height"] + margin_y * 2))
    x = max(0, min(viewport["width"] - width, cx - width / 2))
    y = max(0, min(viewport["height"] - height, cy - height / 2))
    clip = {"x": x, "y": y, "width": width, "height": height}
    page.screenshot(path=path, full_page=False, clip=clip)
    return {
        "mode": "focused-error-region",
        "focus_found": True,
        "focus_selector": {
            "tag": focus.get("tag"),
            "id": focus.get("id"),
            "class": focus.get("className"),
        },
        "focus_text": focus.get("text"),
        "focus_keywords": focus.get("hits") or [],
        "error_signals": focus.get("errorWords") or 0,
        "focus_reason": (
            "Tight crop around the detected error UI with red box, FAILED label and arrow."
        ),
        "clip": clip,
    }


def capture_security_evidence(target: str, findings: list[dict], headed: bool = False,
                              slow_mo: int = 0, max_items: int = 30) -> list[dict]:
    """Capture focused visual evidence for active findings using Chromium and GET-only URLs."""
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
            candidates.append((url, finding.get("id", "security"), finding))
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
        for index, (url, finding_id, finding) in enumerate(candidates, 1):
            page = context.new_page()
            console_errors = []
            page.on("console", lambda msg: console_errors.append(msg.text) if msg.type == "error" else None)
            screenshot = None
            status = None
            error = None
            focus = None
            capture = {}
            try:
                response = page.goto(url, wait_until="domcontentloaded", timeout=30000)
                status = response.status if response else None
                focus = _find_focus(page, finding)
                _marker(page, f"{finding_id} • HTTP {status}")
                if focus:
                    # The marker is intentionally added before annotation so the
                    # report still shows Sentinel context while focusing the error.
                    _annotate_focus(page, focus, finding_id)
                screenshot = os.path.join(
                    EVIDENCE_DIR,
                    f"security_{index:03d}_{_safe_filename(url)}_focused.png",
                )
                capture = _focused_screenshot(page, screenshot, focus)
            except Exception as exc:
                error = f"{type(exc).__name__}: {exc}"
                try:
                    _marker(page, f"{finding_id} • navigation failure")
                    screenshot = os.path.join(
                        EVIDENCE_DIR,
                        f"security_failure_{index:03d}_{_safe_filename(url)}_focused.png",
                    )
                    capture = _focused_screenshot(page, screenshot, None)
                except Exception as screenshot_exc:
                    error += f"; screenshot={type(screenshot_exc).__name__}: {screenshot_exc}"
                    screenshot = None
            finally:
                page.close()

            captured.append({
                "finding_id": finding_id,
                "url": url,
                "status": status,
                "screenshot": screenshot if focus else None,
                "capture": capture,
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
            finding["evidence_focus"] = item.get("capture", {})

    return captured
