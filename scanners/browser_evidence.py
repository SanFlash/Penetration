"""Chrome browser evidence capture with focused error-region screenshots."""
import json
import os
import re
from urllib.parse import urlparse

from playwright.sync_api import sync_playwright
from PIL import Image, ImageDraw, ImageFont

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


def _write_diagnostic_evidence_card(
    path: str, finding: dict, url: str, status, error: str | None, reason: str
) -> dict:
    """Create a clearly marked, readable evidence card when no DOM region is identifiable."""
    try:
        from textwrap import wrap

        def safe_text(value, limit=900):
            text = str(value or "Not provided").replace("\r", " ").replace("\n", " ").strip()
            text = re.sub(
                r"(?i)\b(authorization|cookie|set-cookie|password|passwd|secret|api[_-]?key|access[_-]?token|refresh[_-]?token)\b\s*[:=]\s*[^\s,;]+",
                r"\1=<redacted>",
                text,
            )
            return text[:limit] or "Not provided"

        finding_id = safe_text(finding.get("id") or "SECURITY-FINDING", 60)
        title = safe_text(finding.get("title") or "Security finding", 95)
        severity = safe_text(finding.get("severity") or "Info", 32).upper()
        method = safe_text(finding.get("method") or "GET", 16).upper()
        parameter = safe_text(finding.get("parameter") or "None", 180)
        evidence = safe_text(finding.get("evidence") or finding.get("detail") or "No response excerpt recorded.", 900)
        impact = safe_text(finding.get("impact") or "Review and validate this signal.", 650)
        remediation = safe_text(finding.get("remediation") or "Manually validate the issue and apply the appropriate control.", 650)
        reason_text = safe_text(error or reason or "No browser error text was available.", 900)
        sections = [
            ("TARGET URL", safe_text(url, 500)),
            ("HTTP RESPONSE", f"Status: {status if status is not None else 'n/a'}  |  Method: {method}"),
            ("TEST CONTEXT", f"Parameter/vector: {parameter}"),
            ("OBSERVED EVIDENCE", evidence),
            ("POTENTIAL IMPACT", impact),
            ("RECOMMENDED ACTION", remediation),
            ("CAPTURE NOTE / EXACT ERROR", reason_text),
        ]
        wrapped = [(label, wrap(value, 108)[:6] or ["Not provided"]) for label, value in sections]
        height = 205 + sum(42 + 25 * len(lines) for _, lines in wrapped) + 36
        width = 1400
        image = Image.new("RGB", (width, height), "#07101b")
        draw = ImageDraw.Draw(image)

        def font(size, bold=False):
            try:
                font_path = (
                    "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"
                    if bold else "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"
                )
                return ImageFont.truetype(font_path, size)
            except Exception:
                return ImageFont.load_default()

        draw.text((44, 30), "SENTINEL // DIAGNOSTIC EVIDENCE", fill="#38e8a0", font=font(29, True))
        draw.text((44, 72), "Generated diagnostic artifact — not a webpage screenshot", fill="#8095ab", font=font(17))
        draw.rounded_rectangle((36, 112, width - 36, height - 24), radius=16, outline="#1d2d42", width=2)
        severity_color = {
            "CRITICAL": "#ff4d6d", "HIGH": "#ff8a4c", "MEDIUM": "#ffc857",
            "LOW": "#38e8a0", "INFO": "#7d93ad",
        }.get(severity, "#7d93ad")
        draw.text((60, 132), f"{finding_id}  |  {severity}  |  {title}", fill=severity_color, font=font(20, True))
        y = 174
        for label, lines in wrapped:
            draw.text((60, y), label, fill="#8095ab", font=font(14, True))
            y += 24
            for line_text in lines:
                draw.text((60, y), line_text, fill="#e6eff8", font=font(17))
                y += 25
            y += 16

        image.save(path)
        return {
            "mode": "diagnostic-evidence-card",
            "focus_found": False,
            "capture_scope": "generated-diagnostic-card",
            "focus_reason": reason,
            "diagnostic_artifact": True,
            "annotated": True,
            "finding_id": finding_id,
        }
    except Exception as exc:
        return {
            "mode": "diagnostic-evidence-card-failed",
            "focus_found": False,
            "capture_scope": "none",
            "focus_reason": reason,
            "error": f"{type(exc).__name__}: {exc}",
        }


def _annotate_evidence_image(path: str, finding: dict, url: str, status=None,
                            focus: dict | None = None, full_page: bool = False) -> dict:
    """Embed issue-specific explanation and a visible highlight into a screenshot artifact."""
    from textwrap import wrap

    def clean(value, limit=700):
        text = str(value or "").replace("\\r", " ").replace("\\n", " ").strip()
        text = re.sub(
            r"(?i)\\b(authorization|cookie|set-cookie|password|passwd|secret|api[_-]?key|access[_-]?token|refresh[_-]?token)\\b\\s*[:=]\\s*[^\\s,;]+",
            r"\\1=<redacted>", text,
        )
        return text[:limit] or "Not recorded"

    if not path or not os.path.isfile(path):
        return {"annotated": False, "annotation_error": "Screenshot artifact is missing."}
    try:
        original = Image.open(path).convert("RGB")
        width, height = original.size
        issue_id = clean(finding.get("id") or finding.get("finding_id") or "SENTINEL-FINDING", 70)
        title = clean(finding.get("title") or "Assessment observation", 160)
        severity = clean(finding.get("severity") or "Info", 30).upper()
        summary = clean(finding.get("plain_language_summary") or finding.get("description") or finding.get("detail") or finding.get("evidence"), 600)
        impact = clean(finding.get("impact") or "Validate the security and business impact in the authorized test environment.", 420)
        fix = clean(finding.get("remediation") or finding.get("recommended_action") or "Review the affected component and rerun the relevant check after remediation.", 420)
        observed = clean(finding.get("evidence") or finding.get("detail") or "No additional observed response detail was recorded.", 500)
        severity_color = {
            "CRITICAL": (255, 48, 92), "HIGH": (255, 120, 60),
            "MEDIUM": (255, 190, 55), "LOW": (56, 205, 145),
        }.get(severity, (100, 170, 255))

        def get_font(size, bold=False):
            candidates = (
                ["/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", "C:/Windows/Fonts/arialbd.ttf"]
                if bold else
                ["/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", "C:/Windows/Fonts/arial.ttf"]
            )
            for candidate in candidates:
                try:
                    return ImageFont.truetype(candidate, size)
                except Exception:
                    pass
            return ImageFont.load_default()

        # Use a compact but readable report header; keep original screenshot pixels intact below it.
        font_title, font_body, font_small = get_font(23, True), get_font(16), get_font(13)
        header_h = 240
        canvas = Image.new("RGB", (width, height + header_h), "#07101b")
        draw = ImageDraw.Draw(canvas)
        draw.rectangle((0, 0, width, header_h), fill="#07101b")
        draw.rectangle((0, 0, 12, header_h), fill=severity_color)
        draw.text((30, 18), f"SENTINEL EVIDENCE  |  {issue_id}  |  {severity}", fill=severity_color, font=get_font(18, True))
        draw.text((30, 48), title[:180], fill="#f1f6fc", font=font_title)
        draw.text((30, 83), f"URL: {clean(url, 500)}", fill="#9db2c9", font=font_small)
        draw.text((30, 105), f"HTTP status: {status if status is not None else 'not recorded'}  |  Capture: {'FULL PAGE' if full_page else 'FOCUSED / VIEWPORT'}", fill="#9db2c9", font=font_small)
        sections = [
            ("WHAT WAS OBSERVED", summary if summary != "Not recorded" else observed),
            ("WHY IT MATTERS", impact),
            ("RECOMMENDED FIX", fix),
        ]
        y = 130
        for label, value in sections:
            draw.text((30, y), label, fill="#38e8a0", font=get_font(12, True))
            y += 17
            lines = wrap(value, width=max(40, min(145, (width - 60) // 9)))[:2]
            for line in lines:
                draw.text((30, y), line, fill="#dce8f5", font=font_small)
                y += 16
            y += 3
            if y > header_h - 18:
                break
        canvas.paste(original, (0, header_h))

        # A focused DOM match is highlighted in the full-page image using document coordinates.
        if focus and focus.get("width") and focus.get("height"):
            try:
                scale_x = width / max(float(focus.get("document_width") or width), 1)
                scale_y = height / max(float(focus.get("document_height") or height), 1)
                x1 = int(max(0, float(focus.get("x", 0)) * scale_x))
                y1 = int(max(0, float(focus.get("document_y", focus.get("y", 0))) * scale_y)) + header_h
                x2 = int(min(width - 1, (float(focus.get("x", 0)) + float(focus.get("width", 0))) * scale_x))
                y2 = int(min(height - 1, (float(focus.get("document_y", focus.get("y", 0))) + float(focus.get("height", 0))) * scale_y)) + header_h
                if x2 > x1 and y2 > y1:
                    draw.rectangle((x1, y1, x2, y2), outline=(255, 23, 68), width=max(3, min(8, width // 250)))
                    label = f"ISSUE HIGHLIGHT: {issue_id}"
                    label_font = get_font(16, True)
                    bbox = draw.textbbox((0, 0), label, font=label_font)
                    label_w, label_h = bbox[2] + 16, bbox[3] + 12
                    label_y = max(header_h, y1 - label_h)
                    draw.rectangle((x1, label_y, min(width - 1, x1 + label_w), label_y + label_h), fill=(255, 23, 68))
                    draw.text((x1 + 8, label_y + 5), label, fill="white", font=label_font)
            except Exception:
                pass
        canvas.save(path, format="PNG", optimize=True)
        return {
            "annotated": True, "annotation_version": 1,
            "issue_id": issue_id, "capture_type": "full-page" if full_page else "focused-or-viewport",
            "image_width": canvas.width, "image_height": canvas.height,
            "highlighted": bool(focus and focus.get("width") and focus.get("height")),
        }
    except Exception as exc:
        return {"annotated": False, "annotation_error": f"{type(exc).__name__}: {exc}"}


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


def evidence_finding_key(finding: dict) -> str:
    """Stable identity shared by capture and report attachment, including legacy findings without ids."""
    explicit = finding.get("id") or finding.get("rule_id") or finding.get("finding_id")
    if explicit:
        return str(explicit)
    title = str(finding.get("title") or "security")
    url = str(finding.get("evidence_url") or finding.get("url") or "")
    return f"{title}@{url}"


def _evidence_candidates(target: str, findings: list[dict], max_items: int | None = None) -> list[tuple[str, str, dict]]:
    """Select distinct findings, not just distinct URLs, for individual evidence capture."""
    candidates = []
    seen = set()
    priority = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
    # Build category queues first so a flood of accessibility/overflow signals
    # cannot crowd out functional, security, penetration, or information-leak evidence.
    queues = {}
    ordered_findings = sorted(
        findings,
        key=lambda item: (
            priority.get(str(item.get("severity") or "Info").title(), 5),
            str(item.get("title") or ""),
            str(item.get("url") or ""),
        ),
    )
    for finding in ordered_findings:
        url = finding.get("evidence_url") or finding.get("url")
        finding_id = evidence_finding_key(finding)
        key = (url, finding_id)
        if not url or key in seen:
            continue
        try:
            assert_same_target(target, url)
        except Exception:
            continue
        seen.add(key)
        category = str(finding.get("category") or "Other").strip() or "Other"
        queues.setdefault(category, []).append((url, finding_id, finding))

    # Round-robin across categories: every discovered coverage area gets a
    # chance to attach concrete evidence, including Low and Info observations.
    limit = max(1, len(findings) if max_items is None else int(max_items))
    while queues and len(candidates) < limit:
        for category in list(queues):
            queue = queues[category]
            if queue and len(candidates) < limit:
                candidates.append(queue.pop(0))
            if not queue:
                del queues[category]
    return candidates


def capture_security_evidence(target: str, findings: list[dict], headed: bool = False,
                              slow_mo: int = 0, max_items: int | None = None,
                              progress_callback=None, max_seconds: int = 120,
                              navigation_timeout_ms: int = 12000) -> list[dict]:
    """Capture focused visual evidence for active findings using Chromium and GET-only URLs."""
    assert_in_scope(target)
    os.makedirs(EVIDENCE_DIR, exist_ok=True)

    candidates = _evidence_candidates(target, findings, max_items)
    unlocated = [
        finding for finding in findings
        if not (finding.get("evidence_url") or finding.get("url"))
    ]

    def notify(done, total, finding_id, url, status, item=None):
        if not progress_callback:
            return
        try:
            progress_callback(done, total, finding_id, url, status, item)
        except TypeError:
            # Preserve compatibility with older five-argument callbacks.
            progress_callback(done, total, finding_id, url, status)

    captured = []
    # A finding without a reliable URL still receives a clearly labelled
    # diagnostic card; it is never misrepresented as a browser screenshot.
    for index, finding in enumerate(unlocated, 1):
        finding_id = evidence_finding_key(finding)
        reason = "The scanner did not provide a finding-specific URL; this artifact summarizes the recorded issue without asserting page-level visual proof."
        path = os.path.join(EVIDENCE_DIR, f"security_unlocated_{index:03d}_{_safe_filename(target)}_diagnostic.png")
        diagnostic = _write_diagnostic_evidence_card(path, finding, target, None, reason, reason)
        item = {
            "finding_id": finding_id,
            "title": finding.get("title"),
            "severity": finding.get("severity"),
            "evidence_summary": finding.get("plain_language_summary") or finding.get("description") or finding.get("evidence") or finding.get("detail"),
            "impact": finding.get("impact"),
            "remediation": finding.get("remediation") or finding.get("recommended_action"),
            "url": target, "status": None,
            "screenshot": path if os.path.isfile(path) else None,
            "capture": {
                "mode": "diagnostic-evidence-card-unlocated",
                "focus_found": False,
                "capture_scope": "generated-diagnostic-card",
                "diagnostic_artifact": True,
                "annotated": True,
                "focus_reason": reason,
                "diagnostic_fallback": diagnostic,
            },
            "console_errors": [], "error": reason,
        }
        captured.append(item)
        if item["screenshot"]:
            finding["screenshot"] = item["screenshot"]
            finding["evidence_capture"] = item
        if progress_callback:
            notify(index, len(unlocated), finding_id, target, "diagnostic-only", item)

    if not candidates:
        with open(os.path.join(EVIDENCE_DIR, "security_browser_evidence.json"), "w", encoding="utf-8") as f:
            json.dump(captured, f, indent=2)
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
                # Do not leave selected findings without an attached artifact just
                # because the browser-navigation budget was consumed. These are
                # explicitly labelled diagnostic cards, never represented as page screenshots.
                reason = (
                    f"Browser evidence time budget ({max_seconds}s) was reached after "
                    f"{len(captured)} capture(s); this item was not navigated."
                )
                diagnostic_path = os.path.join(
                    EVIDENCE_DIR,
                    f"security_{index:03d}_{_safe_filename(url)}_budget_diagnostic.png",
                )
                diagnostic = _write_diagnostic_evidence_card(
                    diagnostic_path, finding, url, None, reason, reason
                )
                item = {
                    "finding_id": finding_id,
                    "url": url,
                    "status": None,
                    "screenshot": diagnostic_path if os.path.isfile(diagnostic_path) else None,
                    "capture": {
                        "mode": "diagnostic-evidence-card-time-budget",
                        "focus_found": False,
                        "capture_scope": "generated-diagnostic-card",
                        "diagnostic_artifact": True,
                        "annotated": True,
                        "focus_reason": reason,
                        "diagnostic_fallback": diagnostic,
                    },
                    "console_errors": [],
                    "error": reason,
                    "error_type": "EvidenceTimeBudget",
                    "error_description": reason,
                }
                captured.append(item)
                if progress_callback:
                    notify(index, total, finding_id, url, "diagnostic-only", item)
                continue

            if progress_callback:
                notify(index - 1, total, finding_id, url, "starting", None)

            page = context.new_page()
            console_errors = []
            page.on("console", lambda msg: console_errors.append(msg.text) if msg.type == "error" else None)
            screenshot = None
            full_page_screenshot = None
            status = None
            error = None
            error_type = None
            focus = None
            capture = {}
            full_page_annotation = None
            full_page_capture_error = None
            try:
                response = page.goto(url, wait_until="domcontentloaded", timeout=navigation_timeout_ms)
                status = response.status if response else None
                focus = _find_focus(page, finding)
                if focus:
                    focus["finding_id"] = finding_id
                    try:
                        metrics = page.evaluate("""() => ({
                            scrollY: window.scrollY || 0,
                            documentWidth: Math.max(document.documentElement.scrollWidth, document.documentElement.clientWidth),
                            documentHeight: Math.max(document.documentElement.scrollHeight, document.documentElement.clientHeight)
                        })""")
                        focus["document_y"] = float(focus.get("y", 0)) + float(metrics.get("scrollY", 0))
                        focus["document_width"] = metrics.get("documentWidth")
                        focus["document_height"] = metrics.get("documentHeight")
                    except Exception:
                        pass
                # Capture the whole document after locating the issue so a coordinate highlight can be aligned.
                # Keep this companion separate from the focused proof artifact.
                try:
                    page.wait_for_timeout(250)
                    full_page_screenshot = os.path.join(
                        EVIDENCE_DIR,
                        f"security_{index:03d}_{_safe_filename(url)}_full-page.png",
                    )
                    page.screenshot(path=full_page_screenshot, full_page=True, animations="disabled")
                    if not os.path.isfile(full_page_screenshot):
                        full_page_screenshot = None
                    elif full_page_screenshot:
                        full_page_annotation = _annotate_evidence_image(
                            full_page_screenshot, finding, url, status, focus, full_page=True
                        )
                except Exception as full_page_exc:
                    full_page_screenshot = None
                    full_page_capture_error = f"{type(full_page_exc).__name__}: {full_page_exc}"
                screenshot = os.path.join(
                    EVIDENCE_DIR,
                    f"security_{index:03d}_{_safe_filename(url)}_focused.png",
                )
                capture = _focused_screenshot(page, screenshot, focus)
                if full_page_capture_error:
                    capture["full_page_capture_error"] = full_page_capture_error
                if capture.get("mode") == "focused-element-capture-failed":
                    error = capture.get("error") or capture.get("focus_reason")
                    error_type = "FocusedElementCaptureError"
                    capture["diagnostic_fallback"] = _write_diagnostic_evidence_card(
                        screenshot, finding, url, status, error,
                        capture.get("focus_reason") or "Focused DOM capture failed.",
                    )
                elif capture.get("mode") == "no-focused-region":
                    # A missing focus locator is not a reason to return zero visual evidence.
                    # Capture the real page viewport and label it as context-only, never as focused proof.
                    try:
                        _marker(page, f"CONTEXT ONLY — {finding_id}; target DOM element not isolated")
                        page.screenshot(path=screenshot, full_page=False, animations="disabled")
                        capture["mode"] = "viewport-context-no-focus"
                        capture["capture_scope"] = "viewport-context"
                        capture["focus_reason"] = capture.get("focus_reason") or "No specific DOM element could be isolated; this is page context, not proof of the finding."
                        diagnostic_path = os.path.splitext(screenshot)[0] + "_diagnostic.png"
                        capture["diagnostic_fallback"] = _write_diagnostic_evidence_card(
                            diagnostic_path, finding, url, status, None, capture["focus_reason"]
                        )
                        capture["diagnostic_screenshot"] = diagnostic_path if os.path.isfile(diagnostic_path) else None
                    except Exception as exc:
                        capture["viewport_capture_error"] = f"{type(exc).__name__}: {exc}"
                        capture["diagnostic_fallback"] = _write_diagnostic_evidence_card(
                            screenshot, finding, url, status, None,
                            capture.get("focus_reason") or "No visible DOM failure element exists for this finding.",
                        )
            except Exception as exc:
                error_type = type(exc).__name__
                error = f"{type(exc).__name__}: {exc}"
                screenshot = None
                capture = {
                    "mode": "navigation-failure-no-screenshot",
                    "focus_found": False,
                    "focus_reason": f"Navigation failed before an error DOM element could be captured: {type(exc).__name__}: {exc}",
                    "error_type": type(exc).__name__,
                    "error_description": str(exc),
                }
                screenshot = os.path.join(
                    EVIDENCE_DIR,
                    f"security_{index:03d}_{_safe_filename(url)}_diagnostic.png",
                )
                capture["diagnostic_fallback"] = _write_diagnostic_evidence_card(
                    screenshot, finding, url, status, error, capture["focus_reason"]
                )
            finally:
                page.close()

            # Add issue-specific explanation to the focused/viewport image too. Generated diagnostic
            # cards already contain these fields, so re-annotating them is intentionally skipped.
            primary_annotation = None
            if screenshot and os.path.isfile(screenshot) and not (capture.get("diagnostic_artifact") or (capture.get("diagnostic_fallback") or {}).get("diagnostic_artifact")):
                primary_annotation = _annotate_evidence_image(screenshot, finding, url, status, None, full_page=False)
            item = {
                "finding_id": finding_id,
                "title": finding.get("title"),
                "severity": finding.get("severity"),
                "evidence_summary": finding.get("plain_language_summary") or finding.get("description") or finding.get("evidence") or finding.get("detail"),
                "impact": finding.get("impact"),
                "remediation": finding.get("remediation") or finding.get("recommended_action"),
                "primary_annotation": primary_annotation,
                "full_page_annotation": full_page_annotation,
                "url": url,
                "status": status,
                "screenshot": screenshot if os.path.isfile(screenshot or "") else None,
                "full_page_screenshot": full_page_screenshot if os.path.isfile(full_page_screenshot or "") else None,
                "evidence_artifacts": [
                    {"kind": "focused_or_diagnostic", "path": screenshot}
                    for _ in [0] if screenshot and os.path.isfile(screenshot)
                ] + [
                    {"kind": "full_page", "path": full_page_screenshot}
                    for _ in [0] if full_page_screenshot and os.path.isfile(full_page_screenshot)
                ],
                "capture": capture,
                "console_errors": console_errors[:20],
                "error": error,
                "error_type": error_type,
                "error_description": error,
                "observed_status": status,
                "failure_scope": capture.get("capture_scope") or capture.get("mode"),
            }
            captured.append(item)
            if progress_callback:
                notify(index, total, finding_id, url, "completed" if not error else "failed", item)

        context.close()
        browser.close()

    with open(os.path.join(EVIDENCE_DIR, "security_browser_evidence.json"), "w", encoding="utf-8") as f:
        json.dump(captured, f, indent=2, ensure_ascii=False)

    by_key = {(item["finding_id"], item["url"]): item for item in captured}
    for finding in findings:
        url = finding.get("evidence_url") or finding.get("url")
        finding_id = str(finding.get("id") or finding.get("title") or "security")
        item = by_key.get((finding_id, url))
        if item and (item.get("screenshot") or item.get("full_page_screenshot")):
            finding["evidence_capture"] = item
            finding["evidence_focus"] = item.get("capture", {})
            finding.setdefault("screenshots", [])
            primary_path = item.get("screenshot")
            if primary_path and os.path.isfile(primary_path):
                finding["screenshot"] = primary_path
                if primary_path not in finding["screenshots"]:
                    finding["screenshots"].append(primary_path)
            full_page_path = item.get("full_page_screenshot")
            if full_page_path and os.path.isfile(full_page_path):
                finding["full_page_screenshot"] = full_page_path
                if full_page_path not in finding["screenshots"]:
                    finding["screenshots"].append(full_page_path)
            finding["evidence_artifacts"] = item.get("evidence_artifacts", [])
            # When the page itself could not isolate a DOM node, attach the
            # generated diagnostic card alongside the context viewport so the
            # report still shows the issue-specific markup at the finding.
            diagnostic_path = (item.get("capture") or {}).get("diagnostic_screenshot")
            if diagnostic_path and os.path.isfile(diagnostic_path) and diagnostic_path not in finding["screenshots"]:
                finding["screenshots"].append(diagnostic_path)

    return captured
