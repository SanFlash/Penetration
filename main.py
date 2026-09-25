#!/usr/bin/env python3
"""CLI for safe-lab and authorized website assessment profiles."""
import argparse
import sys
import threading
import time
from datetime import datetime
from urllib.parse import urlparse

import config
from utils.scope import assert_in_scope, assert_same_target, OutOfScopeError
from utils.http_client import TargetConnectionError
from recon.crawler import SafeCrawler
from recon.playwright_recon import authenticated_recon
from scanners import headers as header_scanner
from scanners import xss_probe, sqli_probe, idor_probe
from scanners.compatibility import run_compatibility
from scanners.active_security import run_active_security
from scanners.browser_evidence import capture_security_evidence
from scanners.deep_security import run_deep_security
from scanners.api_surface import run_api_surface
from scanners.intrusive import run_intrusive
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


def _build_dashboard(target, profile, dashboard=True):
    state = DashboardState(target=target, profile=profile)
    dashboard_url = None
    if dashboard:
        dashboard_url = start_dashboard(state, open_browser=True)
        print(f"[DASHBOARD] Live visual console: {dashboard_url}")
    return state, dashboard_url


def _set_telemetry(state, loader):
    def telemetry(**payload):
        now = datetime.now().strftime("%H:%M:%S")
        log = payload.get("log")
        if log and not log.get("time"):
            log["time"] = now
        state.update(**payload)
        if log:
            loader.set(log.get("message", "Assessment running"))
    return telemetry


def run_compatibility_profile(target: str, headed: bool = False, slow_mo: int = 0, dashboard: bool = True):
    state, dashboard_url = _build_dashboard(target, "compatibility", dashboard)
    loader = ConsoleLoader()
    loader.start("Initializing assessment engine")
    telemetry = _set_telemetry(state, loader)

    try:
        banner("STEP 1 — Scope-limited website reconnaissance")
        loader.set("Crawling authorized target")
        state.update(stage="RECONNAISSANCE", detail="Discovering same-host pages and forms.")
        crawler = SafeCrawler(target, max_pages=config.COMPATIBILITY_MAX_PAGES)
        recon = crawler.crawl()
        urls = [p["url"] for p in recon["pages"]]
        state.update(
            stage="RECON COMPLETE",
            detail=f"Discovered {len(urls)} pages and {len(recon['forms'])} forms.",
            log={"time": datetime.now().strftime("%H:%M:%S"), "level": "ok",
                 "message": f"Discovered {len(urls)} pages and {len(recon['forms'])} forms."},
        )
        print(f"\nDiscovered {len(urls)} pages and {len(recon['forms'])} forms.")

        banner("STEP 2 — Chrome-only UI / responsive testing")
        print(f"[VISUAL] {'HEADED Chrome/Chromium window enabled' if headed else 'headless Chrome/Chromium'}")
        if slow_mo:
            print(f"[VISUAL] Playwright slow-motion: {slow_mo} ms")
        result = run_compatibility(
            target,
            urls,
            max_pages=config.COMPATIBILITY_MAX_PAGES,
            headed=headed,
            slow_mo=slow_mo,
            telemetry=telemetry,
        )
        print(f"\nURLs tested: {len(result['urls_tested'])}")
        print(f"Browser engines tested: {sorted({r['browser'] for r in result['results']})}")
        print(f"Viewports tested: {len(sorted({r['viewport'] for r in result['results']}))}")
        print(f"Browser checks completed: {len(result['results'])}")
        print(f"UI/compatibility findings: {len(result['findings'])}")

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
                         "message": f"Header scan complete: {url}"},
                )
            except TargetConnectionError as exc:
                state.update(
                    detail=f"Header scan skipped: {url}",
                    log={"time": datetime.now().strftime("%H:%M:%S"), "level": "warn",
                         "message": f"Header scan skipped for unreachable page: {url}"},
                )
                print(f"  [WARN] Header scan skipped: {exc.url}")

        print(f"Header findings: {len(header_findings)}")

        all_findings = result["findings"] + header_findings
        banner("STEP 4 — Interactive report generation")
        loader.set("Building interactive analytics report")
        state.update(stage="REPORT GENERATION", detail="Aggregating findings, coverage and evidence.")
        metadata = {
            "profile": "compatibility",
            "headed": headed,
            "slow_mo_ms": slow_mo,
            "dashboard_url": dashboard_url,
            "compatibility": result,
        }
        report = generate(target, all_findings, config.EVIDENCE_DIR, metadata=metadata)
        print(f"Findings JSON: {report['json_path']}")
        print(f"Findings HTML: {report['html_path']}")
        print(f"Total findings: {report['report']['total_findings']}")

        banner("ASSESSMENT COMPLETE")
        state.update(
            status="COMPLETE",
            stage="ASSESSMENT COMPLETE",
            detail="Interactive report is ready.",
            progress=100,
            findings=report["report"]["total_findings"],
            log={"time": datetime.now().strftime("%H:%M:%S"), "level": "ok",
                 "message": "Assessment complete. Open reports/report.html."},
        )
        loader.set("Assessment complete")
        return 0
    finally:
        loader.stop()


def _is_exact_target_url(target: str, url: str) -> bool:
    try:
        assert_same_target(target, url)
        return True
    except OutOfScopeError:
        return False


def run_pentest_profile(target: str, headed: bool = False, slow_mo: int = 0, dashboard: bool = True, authorized: bool = False):
    parsed = urlparse(target)
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.netloc:
        raise ValueError("Target must be an absolute http:// or https:// URL.")
    if not authorized and target.rstrip("/") != config.PENTEST_TARGET_ORIGIN.rstrip("/"):
        raise OutOfScopeError("Arbitrary pentest targets require --confirm-authorized.")
    state, dashboard_url = _build_dashboard(target, "pentest", dashboard)
    loader = ConsoleLoader()
    loader.start("Initializing authorized pentest engine")
    telemetry = _set_telemetry(state, loader)
    all_findings = []
    start = time.time()

    try:
        banner("STEP 1 — Scope-limited reconnaissance")
        state.update(stage="RECONNAISSANCE", detail="Discovering same-host pages, query parameters and forms.")
        loader.set("Crawling authorized target")
        crawler = SafeCrawler(target, max_pages=config.COMPATIBILITY_MAX_PAGES)
        recon = crawler.crawl()
        urls = [p["url"] for p in recon["pages"] if _is_exact_target_url(target, p["url"])]
        forms = recon.get("forms", [])
        state.update(
            stage="RECON COMPLETE",
            detail=f"Discovered {len(urls)} pages and {len(forms)} forms.",
            log={"time": datetime.now().strftime("%H:%M:%S"), "level": "ok",
                 "message": f"Recon complete: {len(urls)} pages, {len(forms)} forms."},
        )
        print(f"\nDiscovered {len(urls)} pages and {len(forms)} forms.")

        banner("STEP 2 — Chrome-only UI / responsive evidence")
        print(f"[VISUAL] {'HEADED Chrome/Chromium window enabled' if headed else 'headless Chrome/Chromium'}")
        if slow_mo:
            print(f"[VISUAL] Playwright slow-motion: {slow_mo} ms")
        ui_result = run_compatibility(
            target,
            urls,
            max_pages=config.COMPATIBILITY_MAX_PAGES,
            headed=headed,
            slow_mo=slow_mo,
            telemetry=telemetry,
        )
        all_findings.extend(ui_result["findings"])
        print(f"\nChrome URLs tested: {len(ui_result['urls_tested'])}")
        print(f"Chrome evidence screenshots/results: {len(ui_result['results'])}")
        print(f"UI findings: {len(ui_result['findings'])}")

        banner("STEP 3 — Passive security-header checks")
        loader.set("Scanning security headers")
        state.update(stage="SECURITY HEADERS", detail="Checking transport and response security headers.")
        header_findings = []
        for index, url in enumerate(urls[:config.COMPATIBILITY_MAX_PAGES], 1):
            try:
                header_result = header_scanner.scan(url)
                header_findings.extend(header_result["findings"])
                state.update(
                    detail=f"Header scan {index}/{min(len(urls), config.COMPATIBILITY_MAX_PAGES)}",
                    log={"time": datetime.now().strftime("%H:%M:%S"), "level": "ok",
                         "message": f"Header check {index} complete."},
                )
            except TargetConnectionError:
                state.update(
                    log={"time": datetime.now().strftime("%H:%M:%S"), "level": "warn",
                         "message": f"Header check skipped: {url}"},
                )
        all_findings.extend(header_findings)
        print(f"Header findings: {len(header_findings)}")

        banner("STEP 4 — Bounded active security testing")
        loader.set("Running bounded active security controls")
        state.update(
            stage="ACTIVE SECURITY TESTING",
            detail="Testing CORS, HTTP methods, input reflection, CSRF posture, error disclosure and mixed content.",
        )
        active_result = run_active_security(
            target,
            urls,
            forms,
            telemetry=telemetry,
            max_urls=config.ACTIVE_SECURITY_MAX_URLS,
        )
        all_findings.extend(active_result["findings"])
        print(f"Active URLs tested: {len(active_result['urls_tested'])}")
        print(f"Active checks: {len(active_result['checks'])}")
        print(f"Active findings: {len(active_result['findings'])}")

        banner("STEP 5 — Deep security and API attack-surface assessment")
        loader.set("Running deep non-destructive security assessment")
        state.update(
            stage="DEEP SECURITY TESTING",
            detail="Running bounded same-origin reconnaissance, headers, methods, query mutations, routing and exposure checks.",
        )
        deep_result = run_deep_security(
            target,
            max_urls=config.SECURITY_MAX_URLS,
            max_probes=config.SECURITY_MAX_PROBES,
        )
        all_findings.extend(deep_result["findings"])
        print(f"Deep URLs tested: {len(deep_result['urls_tested'])}")
        print(f"Deep HTTP probes: {deep_result['probe_count']}")
        print(f"Deep raw findings: {len(deep_result['findings'])}")

        api_result = run_api_surface(
            target,
            max_probes=min(config.SECURITY_MAX_PROBES, 100),
        )
        all_findings.extend(api_result.get("findings", []))
        print(f"API specs discovered: {api_result['summary']['specs']}")
        print(f"API endpoints inventoried: {api_result['summary']['endpoints']}")

        banner("STEP 6 — Chrome security evidence capture")
        loader.set("Capturing Chrome evidence for security findings")
        state.update(
            stage="SECURITY EVIDENCE",
            detail="Replaying finding URLs in Chromium and capturing marked screenshots.",
        )
        security_evidence = capture_security_evidence(
            target,
            active_result["findings"] + deep_result["findings"] + api_result.get("findings", []),
            headed=headed,
            slow_mo=slow_mo,
            max_items=30,
        )
        print(f"Security evidence screenshots: {sum(1 for item in security_evidence if item.get('screenshot'))}")

        all_findings = ui_result["findings"] + header_findings + active_result["findings"] + deep_result["findings"] + api_result.get("findings", [])

        banner("STEP 7 — Interactive pentest report")
        loader.set("Building interactive pentest report")
        state.update(stage="REPORT GENERATION", detail="Aggregating findings, coverage and evidence.")
        elapsed = round(time.time() - start, 1)
        metadata = {
            "profile": "pentest",
            "methodology": "OWASP WSTG-aligned bounded assessment",
            "headed": headed,
            "slow_mo_ms": slow_mo,
            "dashboard_url": dashboard_url,
            "recon": {
                "pages_discovered": len(urls),
                "forms_discovered": len(forms),
            },
            "ui_responsive": ui_result,
            "active_security": active_result,
            "deep_security": deep_result,
            "api_surface": api_result,
            "security_evidence": security_evidence,
            "runtime_seconds": elapsed,
        }
        report = generate(target, all_findings, config.EVIDENCE_DIR, metadata=metadata)
        print(f"Findings JSON: {report['json_path']}")
        print(f"Findings HTML: {report['html_path']}")
        print(f"Total findings: {report['report']['total_findings']}")

        banner("PENTEST COMPLETE")
        for sev, count in report["report"]["severity_summary"].items():
            if count:
                print(f"  {sev}: {count}")
        state.update(
            status="COMPLETE",
            stage="PENTEST COMPLETE",
            detail="Interactive pentest report and evidence are ready.",
            progress=100,
            findings=report["report"]["total_findings"],
            checks=(len(ui_result["results"]) + len(active_result["checks"])),
            log={"time": datetime.now().strftime("%H:%M:%S"), "level": "ok",
                 "message": "Pentest complete. Open reports/report.html."},
        )
        loader.set("Pentest complete")
        return 0
    finally:
        loader.stop()


def run_intrusive_profile(target: str, plan_path: str, authorized: bool = False, confirm_intrusive: bool = False, dry_run: bool = False):
    """Run explicitly configured, reversible state-changing tests only."""
    if not authorized:
        print("[BLOCKED] Intrusive mode requires --confirm-authorized.")
        return 1
    if not confirm_intrusive:
        print("[BLOCKED] Intrusive mode requires --confirm-intrusive.")
        print("[INFO] Every operation must be configured against a disposable test resource with rollback.")
        return 1
    banner("CONTROLLED INTRUSIVE MODE — EXPLICIT ROLLBACK REQUIRED")
    print("[MODE] State-changing tests: DISABLED (dry-run)" if dry_run else "[MODE] State-changing tests: ENABLED")
    print("[MODE] Scope: exact supplied origin; redirects disabled")
    print("[MODE] Arbitrary form submission: DISABLED")
    print("[MODE] Brute force / DoS / server command execution: DISABLED")
    print(f"[MODE] Plan: {plan_path}")
    print(f"[MODE] Dry run: {'YES' if dry_run else 'NO'}")
    try:
        result = run_intrusive(
            target,
            plan_path,
            timeout=config.INTRUSIVE_TIMEOUT,
            dry_run=dry_run,
        )
    except (FileNotFoundError, ValueError) as exc:
        print(f"[ERROR] Intrusive plan rejected: {exc}")
        print("[INFO] Use intrusive_plan.example.json as a starting point and configure a disposable test resource.")
        return 2
    summary = result["summary"]
    print("\nIntrusive actions:", summary["actions"])
    print("Action failures:", summary["action_failures"])
    print("Successful rollbacks:", summary["rollbacks_ok"])
    print("FAILED ROLLBACKS:", summary["failed_rollbacks"])
    print("Evidence: evidence/intrusive_security.json")
    if summary["failed_rollbacks"]:
        print("[STOP] One or more rollback operations failed. Do not continue until the test resource is restored manually.")
        return 3
    return 0


def run_security_profile(target: str, max_urls: int | None = None, max_probes: int | None = None):
    """Run security-only testing with no UI/compatibility/browser phase."""
    banner("SECURITY-ONLY MODE — DEEP AUTHORIZED ASSESSMENT")
    print("[MODE] UI/compatibility testing: DISABLED")
    print("[MODE] Browser/Playwright: DISABLED")
    print("[MODE] Security engine: ENABLED")
    print("[MODE] Scope: exact origin of supplied target; redirects disabled")
    print("[MODE] State-changing requests: DISABLED")
    print("[MODE] Credential attacks / DoS / destructive writes: DISABLED")
    print("[MODE] GET / HEAD / OPTIONS / TRACE + controlled header/query probes")

    result = run_deep_security(
        target,
        max_urls=max_urls or config.SECURITY_MAX_URLS,
        max_probes=max_probes or config.SECURITY_MAX_PROBES,
    )

    banner("DEEP SECURITY ASSESSMENT COMPLETE")
    print(f"URLs tested: {len(result['urls_tested'])}")
    print(f"HTTP probes: {result['probe_count']}")
    print(f"Findings: {len(result['findings'])}")
    for sev, count in result["summary"]["by_severity"].items():
        print(f"  {sev}: {count}")
    print(f"Evidence: {config.EVIDENCE_DIR}/deep_security.json")
    print(f"Report: {result['report']['html_path']}")
    return 0


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
            all_findings.append({
                "id": f"COOKIE-{c['name']}",
                "title": f"Session cookie '{c['name']}' missing HttpOnly flag",
                "severity": "Medium",
                "confidence": "High",
                "category": "Session Management",
                "url": target,
                "detail": "A cookie without HttpOnly is readable by JavaScript.",
                "evidence": f"cookie={c['name']} httpOnly=False",
                "impact": "Can increase the impact of XSS.",
                "remediation": "Set HttpOnly on session cookies.",
            })

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
    parser.add_argument(
        "--profile",
        choices=("auto", "lab", "compatibility", "pentest", "security", "intrusive"),
        default="auto",
        help="auto selects pentest for AM Webtech or an explicitly authorized target; lab remains available for localhost",
    )
    parser.add_argument("--headed", action="store_true", help="show Chrome/Chromium browser windows during UI testing")
    parser.add_argument("--slow-mo", type=int, default=0, metavar="MS",
                        help="delay each Playwright action by MS milliseconds (e.g. 500)")
    parser.add_argument("--no-dashboard", action="store_true",
                        help="disable the local visual dashboard")
    parser.add_argument("--confirm-authorized", action="store_true",
                        help="confirm that you own the target or have explicit authorization for arbitrary-target pentesting")
    parser.add_argument("--confirm-intrusive", action="store_true",
                        help="second confirmation for configured state-changing tests with rollback")
    parser.add_argument("--intrusive-plan", default="intrusive_plan.json",
                        help="JSON plan containing only disposable test resources and rollback actions")
    parser.add_argument("--dry-run", action="store_true", help="preview intrusive actions without sending state-changing requests")
    args = parser.parse_args()
    if args.slow_mo < 0 or args.slow_mo > 5000:
        parser.error("--slow-mo must be between 0 and 5000 milliseconds")
    target = args.target.rstrip("/")

    host = target.lower().split("://", 1)[-1].split("/", 1)[0].split(":")[0]
    is_amwebtech = host in {"amwebtech.com", "www.amwebtech.com"}

    if args.profile == "auto":
        if is_amwebtech:
            profile = "pentest"
        elif args.confirm_authorized:
            profile = "pentest"
        else:
            profile = "lab"
    else:
        profile = args.profile

    print(f"[PROFILE] {profile}")

    if profile in {"security", "intrusive"}:
        if not args.confirm_authorized:
            print("[BLOCKED] Security profile requires --confirm-authorized.")
            print("[INFO] Use only on a system you own or are explicitly authorized to assess.")
            return 1
        print(f"[SCOPE] {profile} profile accepts an arbitrary absolute http(s) target.")
    else:
        banner("STEP 0 — Scope check")
        if profile == "pentest":
            if not args.confirm_authorized and not is_amwebtech:
                print("[BLOCKED] Arbitrary pentest targets require --confirm-authorized.")
                print("[INFO] Use only on a system you own or have explicit authorization to assess.")
                return 1
            print("[OK] Pentest target accepted; every request remains locked to the supplied origin.")
        else:
            try:
                assert_in_scope(target + "/")
            except OutOfScopeError as exc:
                print(f"[BLOCKED] {exc}")
                return 1
            print(f"[OK] {target} is in config.ALLOWED_HOSTS — proceeding.")

    try:

        if profile == "compatibility":
            return run_compatibility_profile(
                target, headed=args.headed, slow_mo=args.slow_mo,
                dashboard=not args.no_dashboard
            )

        if profile == "pentest":
            return run_pentest_profile(
                target, headed=args.headed, slow_mo=args.slow_mo,
                dashboard=not args.no_dashboard, authorized=args.confirm_authorized
            )

        if profile == "security":
            if args.headed or args.slow_mo or args.no_dashboard:
                print("[NOTE] security-only mode ignores UI/dashboard flags.")
            return run_security_profile(target)

        if profile == "intrusive":
            return run_intrusive_profile(
                target,
                plan_path=args.intrusive_plan,
                authorized=args.confirm_authorized,
                confirm_intrusive=args.confirm_intrusive,
                dry_run=args.dry_run,
            )

        if args.headed or args.slow_mo or args.no_dashboard:
            print("[NOTE] visual/browser options are primarily used by compatibility and pentest profiles.")

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
