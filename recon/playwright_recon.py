"""
recon/playwright_recon.py — authenticated, JS-aware reconnaissance.

A plain HTTP crawler (recon/crawler.py) never executes JavaScript, so it
misses anything a single-page app loads dynamically via fetch/XHR. This
module drives a real (headless) browser with Playwright, logs in, and
records every network request the rendered page actually makes — which is
exactly what a requests-based crawler cannot see.

Scope is enforced the same way as everywhere else: only in-scope hosts are
visited (checked before every .goto()), and a screenshot is captured after
each navigation as evidence.
"""
import json
import os

from playwright.sync_api import sync_playwright

from config import EVIDENCE_DIR
from utils.scope import assert_in_scope


def authenticated_recon(base_url: str, username: str, password: str) -> dict:
    assert_in_scope(base_url)
    os.makedirs(EVIDENCE_DIR, exist_ok=True)
    captured_requests = []

    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=True)
        page = browser.new_page()
        page.on("request", lambda req: captured_requests.append({
            "method": req.method, "url": req.url, "resource_type": req.resource_type,
        }))

        assert_in_scope(f"{base_url}/login")
        page.goto(f"{base_url}/login")
        page.fill('input[name="username"]', username)
        page.fill('input[name="password"]', password)
        page.click("button")
        page.wait_for_load_state("networkidle")
        page.screenshot(path=os.path.join(EVIDENCE_DIR, "after_login.png"))

        assert_in_scope(f"{base_url}/products?name=Widget")
        page.goto(f"{base_url}/products?name=Widget")
        page.wait_for_load_state("networkidle")
        page.screenshot(path=os.path.join(EVIDENCE_DIR, "products_page.png"))

        cookies = page.context.cookies()
        browser.close()

    api_endpoints = sorted({
        r["url"] for r in captured_requests
        if "/api/" in r["url"] or "/products" in r["url"] or "/search" in r["url"]
    })
    result = {
        "api_endpoints": api_endpoints,
        "cookies": [{"name": c["name"], "httpOnly": c.get("httpOnly", False),
                     "secure": c.get("secure", False)} for c in cookies],
        "total_requests_observed": len(captured_requests),
    }
    with open(os.path.join(EVIDENCE_DIR, "playwright_recon.json"), "w") as f:
        json.dump(result, f, indent=2)
    return result
