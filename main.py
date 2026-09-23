#!/usr/bin/env python3
"""CLI for safe-lab and authorized website assessment profiles."""
import argparse
import sys
import threading
import time
from datetime import datetime

import config
from utils.scope import assert_in_scope, OutOfScopeError
from utils.http_client import TargetConnectionError
from recon.crawler import SafeCrawler
from recon.playwright_recon import authenticated_recon
from scanners import headers as header_scanner
from scanners import xss_probe, sqli_probe, idor_probe
from scanners.compatibility import run_compatibility
from auth.session import login
from reports.report_generator import generate
from ui.dashboard import DashboardState, start_dashboard


class ConsoleLoader:
    def __init__(self):
        self.running = False
        self.thread = None
        self.message = "Working"

    def start(self, message="Working"):
        self.message = message
        self.running = True
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def set(self, message):
        self.message = message

    def stop(self):
        self.running = False
        if self.thread:
            self.thread.join(timeout=1)
        print("\r" + " " * 100 + "\r", end="", flush=True)

    def _run(self):
        frames = "|/-\\"
        i = 0
        while self.running:
            print(f"\r[{frames[i % len(frames)]}] {self.message}", end="", flush=True)
            i += 1
            time.sleep(.12)


def banner(text):
    print("\n" + "=" * 74)
    print(text)
    print("=" * 74)


def run_compatibility_profile(target: str, headed: bool = False, slow_mo: int = 0, dashboard: bool = True):
    state = DashboardState(target=target, profile="compatibility")
    dashboard_url = None
    if dashboard:
        dashboard_url = start_dashboard(state, open_browser=True)
        print(f"[DASHBOARD] Live visual console: {dashboard_url}")

    def telemetry(**payload):
        now = datetime.now().strftime("%H:%M:%S")
        log = payload.get("log")
        if log and not log.get("time"):
            log["time"] = now
        state.update(**payload)
        if log:
            loader.set(log.get("message", "Assessment running"))

    loader = ConsoleLoader()
    loader.start("Initializing assessment engine")

    try:
        banner("STEP 1 — Scope-limited website reconnaissance")
        loader.set("Crawling authorized target")
        state.update(stage="RECONNAISSANCE", detail="Discovering same-host pages and forms.",
                     log={"time": datetime.now().strftime("%H:%M:%S"), "level":"ok", "message":"Reconnaissance started."})
        crawler = SafeCrawler(target, max_pages=config.COMPATIBILITY_MAX_PAGES)
        recon = crawler.crawl()
        urls = [p["url"] for p in recon["pages"]]
        state.update(stage="RECON COMPLETE",
                     detail=f"Discovered {len(urls)} pages and {len(recon['forms'])} forms.",
                     log={"time": datetime.now().strftime("%H:%M:%S"), "level":"ok",
                          "message":f"Discovered {len(urls)} pages and {len(recon['forms'])} forms."})
        print(f"\nDiscovered {len(urls)} pages and {len(recon['forms'])} forms.")

        banner("STEP 2 — Cross-browser / responsive compatibility")
        print(f"[VISUAL] {'HEADED browser windows enabled' if headed else 'headless browser engines'}")
        if slow_mo:
            print(f"[VISUAL] Playwright slow-motion: {slow_mo} ms")
        result = run_compatibility(target, urls, max_pages=config.COMPATIBILITY_MAX_PAGES,
                                   headed=headed, slow_mo=slow_mo, telemetry=telemetry)
        print(f"\nURLs tested: {len(result['urls_tested'])}")
        print(f"Browser engines available: {sorted({r['browser'] for r in result['results']})}")
        print(f"Viewports tested: {len(sorted({r['viewport'] for r in result['results']}))}")
        print(f"Browser checks completed: {len(result['results'])}")
        print(f"Compatibility findings: {len(result['findings'])}")

        if result["browser_unavailable"]:
            print("Unavailable browser engines:")
            for item in result["browser_unavailable"]:
                print(f"  {item['browser']}: {item['reason']}")

        banner("STEP 3 — Passive security/header checks")
        loader.set("Scanning security headers")
        state.update(stage="SECURITY HEADERS", detail="Running passive response-header checks.")
        header_findings = []
        header_urls = urls[:config.COMPATIBILITY_MAX_PAGES]
        for index, url in enumerate(header_urls, 1):
            try:
                header_result = header_scanner.scan(url)
                header_findings.extend(header_result["findings"])
                state.update(
                    detail=f"Header scan {index}/{len(header_urls)}",
                    log={"time": datetime.now().strftime("%H:%M:%S"), "level": "ok",
                         "message": f"Header scan complete: {url}"}
                )
            except TargetConnectionError as exc:
                state.update(
                    detail=f"Header scan skipped: {url}",
                    log={"time": datetime.now().strftime("%H:%M:%S"), "level": "warn",
                         "message": f"Header scan skipped for unreachable page: {url}"}
                )
                print(f"  [WARN] Header scan skipped: {exc.url}")
        print(f"Header findings: {len(header_findings)}")

        all_findings = result["findings"] + header_findings
        banner("STEP 4 — Interactive report generation")
        loader.set("Building interactive analytics report")
        state.update(stage="REPORT GENERATION", detail="Aggregating findings, coverage and evidence.")
        metadata = {"profile":"compatibility","headed":headed,"slow_mo_ms":slow_mo,
                    "dashboard_url":dashboard_url,"compatibility":result}
        report = generate(target, all_findings, config.EVIDENCE_DIR, metadata=metadata)
        print(f"Findings JSON: {report['json_path']}")
        print(f"Findings HTML: {report['html_path']}")
        print(f"Total findings: {report['report']['total_findings']}")

        banner("ASSESSMENT COMPLETE")
        for sev, count in report["report"]["severity_summary"].items():
            if count:
                print(f"  {sev}: {count}")
        state.update(status="COMPLETE", stage="ASSESSMENT COMPLETE",
                     detail="Interactive report is ready.", progress=100,
                     findings=report["report"]["total_findings"],
                     log={"time": datetime.now().strftime("%H:%M:%S"), "level":"ok",
                          "message":"Assessment complete. Open reports/report.html."})
        loader.set("Assessment complete")
        return 0
    finally:
        loader.stop()


def run_lab_full_profile(target: str):
    all_findings = []
    start = time.time()
    banner("STEP 1 — Reconnaissance (scope-limited crawler)")
    crawler = SafeCrawler(target)
    recon_result = crawler.crawl()
    print(f"Discovered {len(recon_result['pages'])} pages, {len(recon_result['forms'])} forms.")
    for pg in recon_result["pages"]:
        print(f"  {pg['status']}  {pg['url']}")

    banner("STEP 2 — Authenticated recon (Playwright)")
    pw_result = authenticated_recon(target, config.DEMO_USERNAME, config.DEMO_PASSWORD)
    print(f"Observed {pw_result['total_requests_observed']} network requests.")
    print(f"API-shaped endpoints found: {pw_result['api_endpoints']}")
    for c in pw_result["cookies"]:
        print(f"  cookie '{c['name']}': httpOnly={c['httpOnly']} secure={c['secure']}")
        if not c["httpOnly"]:
            all_findings.append({"id":f"COOKIE-{c['name']}","title":f"Session cookie '{c['name']}' missing HttpOnly flag",
                                 "severity":"Medium","confidence":"High","category":"Session Management","url":target,
                                 "detail":"A cookie without HttpOnly is readable by JavaScript.",
                                 "evidence":f"cookie={c['name']} httpOnly=False","impact":"Can increase the impact of XSS.",
                                 "remediation":"Set HttpOnly on session cookies."})

    banner("STEP 3 — Security header scan")
    header_result = header_scanner.scan(target + "/")
    print(f"Headers present: {list(header_result['headers_present'].keys())}")
    print(f"Headers missing: {header_result['headers_missing']}")
    all_findings.extend(header_result["findings"])

    banner("STEP 4 — Reflected XSS probe on /search?q=")
    xss_result = xss_probe.probe_param(target + "/search", "q")
    print(f"Marker reflected unescaped: {xss_result['reflected_unescaped']}")
    all_findings.extend(xss_result["findings"])

    banner("STEP 5 — SQL injection probe on /products?name=")
    sqli_result = sqli_probe.probe_param(target + "/products", "name")
    print(f"Error-based signal: {sqli_result['error_triggered']}  Boolean-based signal: {sqli_result['boolean_diff']}")
    all_findings.extend(sqli_result["findings"])

    banner("STEP 6 — IDOR probe on /api/orders/{id}")
    session = login(target, config.DEMO_USERNAME, config.DEMO_PASSWORD)
    idor_result = idor_probe.probe_endpoint(session, target, "/api/orders/{id}", owned_id=2, other_id=1)
    print(f"Own={idor_result['owned_status']} Other={idor_result['other_status']} Vulnerable={idor_result['vulnerable']}")
    all_findings.extend(idor_result["findings"])

    banner("STEP 6b — Secure control endpoint")
    secure = idor_probe.probe_endpoint(session, target, "/api/orders-secure/{id}", owned_id=2, other_id=1)
    print(f"Own={secure['owned_status']} Other={secure['other_status']} Vulnerable={secure['vulnerable']}")

    banner("STEP 7 — Report generation")
    result = generate(target, all_findings, config.EVIDENCE_DIR)
    elapsed = round(time.time() - start, 1)
    print(f"Findings JSON: {result['json_path']}")
    print(f"Findings HTML: {result['html_path']}")
    print(f"Total findings: {result['report']['total_findings']} (run completed in {elapsed}s)")
    for sev, count in result["report"]["severity_summary"].items():
        if count:
            print(f"  {sev}: {count}")
    return 0


def main():
    parser = argparse.ArgumentParser(description="Authorized web assessment framework")
    parser.add_argument("--target", default=config.DEFAULT_TARGET, help="Base URL of an IN-SCOPE target")
    parser.add_argument("--profile", choices=("auto","lab","compatibility"), default="auto",
                        help="auto selects compatibility for AM Webtech and lab for localhost")
    parser.add_argument("--headed", action="store_true", help="show Playwright browser windows during compatibility testing")
    parser.add_argument("--slow-mo", type=int, default=0, metavar="MS",
                        help="delay each Playwright action by MS milliseconds (e.g. 500)")
    parser.add_argument("--no-dashboard", action="store_true",
                        help="disable the local visual dashboard for compatibility runs")
    args = parser.parse_args()
    if args.slow_mo < 0 or args.slow_mo > 5000:
        parser.error("--slow-mo must be between 0 and 5000 milliseconds")
    target = args.target.rstrip("/")

    banner("STEP 0 — Scope check")
    try:
        assert_in_scope(target + "/")
    except OutOfScopeError as exc:
        print(f"[BLOCKED] {exc}")
        return 1
    print(f"[OK] '{target}' is in config.ALLOWED_HOSTS — proceeding.")

    try:
        host = target.lower().split("://",1)[-1].split("/",1)[0].split(":")[0]
        is_amwebtech = host in {"amwebtech.com","www.amwebtech.com"}
        profile = "compatibility" if args.profile == "auto" and is_amwebtech else args.profile
        if profile == "auto":
            profile = "lab"
        print(f"[PROFILE] {profile}")
        if profile == "compatibility":
            return run_compatibility_profile(target, headed=args.headed, slow_mo=args.slow_mo,
                                             dashboard=not args.no_dashboard)
        if args.headed or args.slow_mo or args.no_dashboard:
            print("[NOTE] visual/dashboard options are used by the compatibility profile.")
        return run_lab_full_profile(target)
    except TargetConnectionError as exc:
        print("\n[ERROR] Target is unreachable.")
        print(f"  Target: {exc.url}")
        print("  Check that the authorized target is running and the host/port is correct.")
        print("  Local lab: python demo_target/app.py")
        return 2
    except KeyboardInterrupt:
        print("\n[STOPPED] Assessment interrupted by user.")
        return 130


if __name__ == "__main__":
    sys.exit(main())
