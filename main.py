#!/usr/bin/env python3
"""CLI for safe-lab and authorized website assessment profiles."""
import argparse
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
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
from scanners.browser_evidence import capture_security_evidence, capture_target_overview
from scanners.deep_security import run_deep_security
from scanners.api_surface import run_api_surface
from scanners.input_stress import run_input_stress
from scanners.input_validation import run_input_validation
from scanners.aggressive_readonly import run_aggressive_readonly
from scanners.comprehensive_security import run_comprehensive_security
from scanners.route_discovery import run_route_discovery
from scanners.attack_surface import correlate_attack_surface
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
        report = generate(target, all_findings, config.EVIDENCE_DIR, out_dir=config.REPORT_DIR, metadata=metadata)
        print(f"Findings JSON: {report['json_path']}")
        print(f"Findings HTML: {report['html_path']}")
        print(f"Portable HTML: {report.get('portable_html_path', '-')}")
        print(f"PDF report: {report.get('pdf_path') or 'not generated (open portable HTML and Print -> Save as PDF)'}")
        print(f"XLSX report: {report.get('xlsx_path', '-')}")

        print(f"Total findings: {report['report']['total_findings']}")
        remediation = report["report"].get("remediation", {})
        priority_counts = remediation.get("priority_counts", {})
        print(
            "Remediation priorities: "
            f"Immediate={priority_counts.get('Immediate', 0)} | "
            f"High={priority_counts.get('High', 0)} | "
            f"Planned={priority_counts.get('Planned', 0)} | "
            f"Review={priority_counts.get('Review', 0)}"
        )
        for action in remediation.get("actions", [])[:5]:
            print(
                f"  [FIX] {action.get('severity', 'Info')} — {action.get('title', 'Untitled')}"
                f" | Impact: {action.get('impact', '')}"
                f" | Solve: {action.get('fix', '')}"
            )

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


def _phase_call(name, phase_status, fn):
    """Run one assessment phase without allowing a single broken scanner to abort the whole report."""
    started = time.monotonic()
    try:
        value = fn()
        phase_status[name] = {
            "status": "completed",
            "duration_seconds": round(time.monotonic() - started, 2),
        }
        return value
    except Exception as exc:
        phase_status[name] = {
            "status": "failed",
            "duration_seconds": round(time.monotonic() - started, 2),
            "error": f"{type(exc).__name__}: {exc}",
        }
        print(f"[WARN] Phase '{name}' failed: {type(exc).__name__}: {exc}", flush=True)
        return None


def _refresh_live_report(target, findings, metadata):
    """Regenerate the HTML/JSON report after each completed phase.

    This makes the report useful while a long assessment is still running and
    preserves evidence collected before a later scanner fails.
    """
    try:
        return generate(
            target,
            list(findings),
            config.EVIDENCE_DIR,
            out_dir=config.REPORT_DIR,
            metadata=dict(metadata),
        )
    except Exception as exc:
        print(f"[WARN] Live report refresh failed: {type(exc).__name__}: {exc}", flush=True)
        return None


def run_pentest_profile(target: str, headed: bool = False, slow_mo: int = 0, dashboard: bool = True, authorized: bool = False, state_override=None):
    parsed = urlparse(target)
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.netloc:
        raise ValueError("Target must be an absolute http:// or https:// URL.")
    if not authorized and target.rstrip("/") != config.PENTEST_TARGET_ORIGIN.rstrip("/"):
        raise OutOfScopeError("Arbitrary pentest targets require --confirm-authorized.")

    if state_override is not None:
        state, dashboard_url = state_override, None
    else:
        state, dashboard_url = _build_dashboard(target, "pentest", dashboard)

    loader = ConsoleLoader()
    loader.start("Initializing authorized pentest engine")
    telemetry = _set_telemetry(state, loader)
    phase_status = {}
    all_findings = []
    start = time.time()

    recon = {"pages": [], "forms": []}
    discovery_result = {"pages": [], "assets": [], "routes": [], "summary": {}, "findings": []}
    target_overview = {}
    ui_result = {"results": [], "findings": [], "urls_tested": []}
    header_findings = []
    active_result = {"findings": [], "checks": [], "urls_tested": []}
    deep_result = {"findings": [], "checks": [], "urls_tested": [], "probe_count": 0}
    api_result = {"findings": [], "checks": [], "summary": {"specs": 0, "endpoints": 0}}
    aggressive_result = {"findings": [], "checks": [], "probes": 0, "summary": {"candidate_points": 0}}
    comprehensive_result = {"findings": [], "checks": [], "probes": 0, "summary": {"urls_tested": 0}}
    stress_result = {"findings": [], "checks": [], "probes": 0, "summary": {"candidate_points": 0}}
    validation_result = {"findings": [], "checks": [], "probes": 0, "summary": {"candidate_points": 0, "valid_cases": 0, "invalid_cases": 0, "accepted_invalid_2xx": 0}}
    security_evidence = []
    attack_surface = {"summary": {}, "routes": []}
    urls = []
    forms = []

    def current_metadata(status="RUNNING"):
        return {
            "profile": "pentest",
            "status": status,
            "methodology": "OWASP WSTG-aligned bounded assessment",
            "report_language": "plain-language-first",
            "headed": headed,
            "slow_mo_ms": slow_mo,
            "dashboard_url": dashboard_url,
            "phase_status": phase_status,
            "recon": {"pages_discovered": len(urls), "forms_discovered": len(forms)},
            "attack_surface_discovery": discovery_result,
            "aggressive_readonly": aggressive_result,
            "comprehensive_security": comprehensive_result,
            "target_overview": target_overview,
            "ui_responsive": ui_result,
            "active_security": active_result,
            "deep_security": deep_result,
            "api_surface": api_result,
            "attack_surface": attack_surface,
            "input_stress": stress_result,
            "input_validation": validation_result,
            "security_evidence": security_evidence,
            "runtime_seconds": round(time.time() - start, 1),
        }

    last_report_refresh = 0.0

    def refresh_report(stage, detail, force=False):
        nonlocal last_report_refresh
        now = time.monotonic()
        min_interval = float(getattr(config, "LIVE_REPORT_MIN_INTERVAL", 12))
        if not force and last_report_refresh and (now - last_report_refresh) < min_interval:
            state.update(stage=stage, detail=detail, findings=len(all_findings))
            return None
        report = _refresh_live_report(target, all_findings, current_metadata("RUNNING"))
        if report:
            last_report_refresh = now
        count = report["report"]["total_findings"] if report else len(all_findings)
        state.update(
            stage=stage,
            detail=detail,
            findings=count,
            log={"time": datetime.now().strftime("%H:%M:%S"), "level": "ok",
                 "message": f"Live report updated: {count} findings."},
        )
        return report

    def finish_phase(name, stage, detail, result=None):
        refresh_report(stage, detail)
        return result

    try:
        banner("STEP 1 — Scope-limited reconnaissance")
        state.update(stage="RECONNAISSANCE", detail="Discovering same-origin pages, query parameters and forms.")
        loader.set("Crawling authorized target")
        value = _phase_call(
            "reconnaissance",
            phase_status,
            lambda: SafeCrawler(target, max_pages=config.COMPATIBILITY_MAX_PAGES).crawl(),
        )
        if value:
            recon = value
        urls = [p.get("url") for p in recon.get("pages", []) if p.get("url") and _is_exact_target_url(target, p["url"])]
        forms = recon.get("forms", [])
        print(f"Discovered {len(urls)} pages and {len(forms)} forms.")
        refresh_report("RECON COMPLETE", f"Discovered {len(urls)} pages and {len(forms)} forms.")

        banner("STEP 2 — Deep attack-surface discovery")
        loader.set("Expanding route, sitemap and JavaScript discovery")
        value = _phase_call(
            "attack_surface_discovery",
            phase_status,
            lambda: run_route_discovery(
                target,
                max_pages=config.ROUTE_DISCOVERY_MAX_PAGES,
                max_assets=config.ROUTE_DISCOVERY_MAX_ASSETS,
                max_candidates=config.ROUTE_DISCOVERY_MAX_CANDIDATES,
            ),
        )
        if value:
            discovery_result = value
            discovered_pages = [u for u in value.get("pages", []) if _is_exact_target_url(target, u)]
            discovered_get_routes = [
                row.get("url") for row in value.get("routes", [])
                if row.get("method", "GET").upper() == "GET"
                and row.get("url")
                and _is_exact_target_url(target, row["url"])
            ]
            urls = list(dict.fromkeys(urls + discovered_pages + discovered_get_routes))[:config.PENTEST_MAX_DISCOVERED_URLS]
        print(f"Expanded in-scope URL inventory: {len(urls)}")
        print(f"Discovered JS/assets: {len(discovery_result.get('assets', []))}")
        print(f"Discovered route candidates: {len(discovery_result.get('routes', []))}")
        refresh_report("ATTACK-SURFACE DISCOVERY", f"Expanded inventory to {len(urls)} same-origin URLs.")

        banner("STEP 3 — Target website visual overview")
        loader.set("Capturing target website overview")
        target_overview = _phase_call(
            "target_overview",
            phase_status,
            lambda: capture_target_overview(target, headed=headed, slow_mo=slow_mo),
        ) or {}
        refresh_report("TARGET OVERVIEW", "Target overview evidence is available in the report.")

        banner("STEP 4 — Chrome UI / responsive evidence")
        loader.set("Running Chromium UI and responsive coverage")
        value = _phase_call(
            "ui_responsive",
            phase_status,
            lambda: run_compatibility(
                target, urls, max_pages=config.COMPATIBILITY_MAX_PAGES,
                headed=headed, slow_mo=slow_mo, telemetry=telemetry,
            ),
        )
        if value:
            ui_result = value
            all_findings.extend(value.get("findings", []))
        print(f"Chrome URLs tested: {len(ui_result.get('urls_tested', []))}")
        print(f"UI findings: {len(ui_result.get('findings', []))}")
        refresh_report("UI / RESPONSIVE TESTING", f"Chrome testing completed across {len(ui_result.get('urls_tested', []))} URLs.")

        banner("STEP 5 — Security headers")
        loader.set("Checking security headers")
        header_findings = []
        for index, url in enumerate(urls[:config.SECURITY_MAX_URLS], 1):
            try:
                result = header_scanner.scan(url)
                header_findings.extend(result.get("findings", []))
            except Exception as exc:
                phase_status.setdefault("security_headers", {"status": "partial"})
                print(f"[WARN] Header check skipped {url}: {type(exc).__name__}: {exc}")
            if index % 10 == 0 or index == len(urls[:config.SECURITY_MAX_URLS]):
                state.update(detail=f"Security headers: {index}/{min(len(urls), config.SECURITY_MAX_URLS)}")
        all_findings.extend(header_findings)
        phase_status["security_headers"] = {
            "status": "completed",
            "urls_tested": min(len(urls), config.SECURITY_MAX_URLS),
            "findings": len(header_findings),
        }
        refresh_report("SECURITY HEADERS", f"Header assessment completed for {len(header_findings)} observations.")

        banner("STEP 6 — Active security")
        loader.set("Running bounded active security controls")
        value = _phase_call(
            "active_security",
            phase_status,
            lambda: run_active_security(
                target, urls, forms, telemetry=telemetry,
                max_urls=config.ACTIVE_SECURITY_MAX_URLS,
            ),
        )
        if value:
            active_result = value
            all_findings.extend(value.get("findings", []))
        refresh_report("ACTIVE SECURITY", f"Active security testing completed with {len(active_result.get('findings', []))} observations.")

        banner("STEP 7 — Parallel read-only security engines")
        loader.set("Running parallel bounded security engines")
        scan_urls = urls[:config.PENTEST_MAX_DISCOVERED_URLS]
        url_count = max(1, len(scan_urls))

        # Adaptive budgets preserve broad URL coverage without forcing every
        # engine to consume its maximum probe budget on small/medium sites.
        deep_budget = min(config.SECURITY_MAX_PROBES, max(120, url_count * 6))
        api_budget = min(config.SECURITY_MAX_PROBES, max(100, url_count * 4), 250)
        aggressive_budget = min(config.AGGRESSIVE_MAX_PROBES, max(120, url_count * 6))
        comprehensive_budget = min(config.COMPREHENSIVE_MAX_PROBES, max(120, url_count * 6))
        stress_budget = min(config.STRESS_MAX_PROBES, max(120, url_count * 5))
        validation_budget = min(config.VALIDATION_MAX_PROBES, max(100, url_count * 4))

        jobs = {
            "deep_security": lambda: run_deep_security(
                target, max_urls=min(config.SECURITY_MAX_URLS, url_count), max_probes=deep_budget
            ),
            "api_surface": lambda: run_api_surface(target, max_probes=api_budget),
            "aggressive_readonly": lambda: run_aggressive_readonly(
                target, scan_urls, max_urls=min(config.AGGRESSIVE_MAX_URLS, url_count), max_probes=aggressive_budget
            ),
            "comprehensive_security": lambda: run_comprehensive_security(
                target, urls=scan_urls, max_urls=min(config.COMPREHENSIVE_MAX_URLS, url_count), max_probes=comprehensive_budget
            ),
            "input_stress": lambda: run_input_stress(
                target, scan_urls, max_urls=min(config.STRESS_MAX_URLS, url_count), max_probes=stress_budget
            ),
            "input_validation": lambda: run_input_validation(
                target, scan_urls, max_urls=min(config.VALIDATION_MAX_URLS, url_count), max_probes=validation_budget
            ),
        }

        results = {}
        # Three concurrent workers reduce wall-clock time while avoiding an
        # uncontrolled request burst against the authorized target.
        with ThreadPoolExecutor(max_workers=3, thread_name_prefix="sentinel-scan") as pool:
            futures = {pool.submit(_phase_call, name, phase_status, fn): name for name, fn in jobs.items()}
            for future in as_completed(futures):
                name = futures[future]
                value = future.result()
                results[name] = value
                if value:
                    if name == "deep_security":
                        deep_result = value
                    elif name == "api_surface":
                        api_result = value
                    elif name == "aggressive_readonly":
                        aggressive_result = value
                    elif name == "comprehensive_security":
                        comprehensive_result = value
                    elif name == "input_stress":
                        stress_result = value
                    elif name == "input_validation":
                        validation_result = value
                    all_findings.extend(value.get("findings", []))
                state.update(detail=f"{name.replace('_', ' ').title()} finished")

        refresh_report(
            "PARALLEL SECURITY TESTING",
            f"Completed six read-only security engines across {url_count} discovered URLs."
        )

        attack_surface = _phase_call(
            "attack_surface_correlation",
            phase_status,
            lambda: correlate_attack_surface(target, recon=recon, route_discovery=discovery_result, api_surface=api_result),
        ) or attack_surface
        refresh_report("ATTACK-SURFACE CORRELATION", "Routes and API candidates were correlated into the assessment inventory.")

        banner("STEP 10 — Focused browser evidence")
        loader.set("Capturing focused evidence for detected issues")
        evidence_findings = (
            active_result.get("findings", [])
            + deep_result.get("findings", [])
            + api_result.get("findings", [])
            + aggressive_result.get("findings", [])
            + comprehensive_result.get("findings", [])
            + stress_result.get("findings", [])
            + validation_result.get("findings", [])
        )
        value = _phase_call(
            "security_evidence",
            phase_status,
            lambda: capture_security_evidence(
                target, evidence_findings, headed=headed,
                slow_mo=slow_mo, max_items=50,
            ),
        )
        if value:
            security_evidence = value
        refresh_report("SECURITY EVIDENCE", f"Focused evidence captured for {sum(1 for x in security_evidence if x.get('screenshot'))} issues.")

        banner("STEP 11 — Final interactive report")
        loader.set("Finalizing HTML report")
        phase_status["report_generation"] = {"status": "completed"}
        phase_failures = [name for name, info in phase_status.items() if info.get("status") == "failed"]
        final_status = "PARTIAL" if phase_failures else "COMPLETE"
        report = _refresh_live_report(target, all_findings, current_metadata(final_status))
        last_report_refresh = time.monotonic()
        if not report:
            raise RuntimeError("The assessment completed but the HTML report could not be generated.")

        print(f"Findings JSON: {report['json_path']}")
        print(f"Findings HTML: {report['html_path']}")
        print(f"Portable HTML: {report.get('portable_html_path', '-')}")
        print(f"PDF report: {report.get('pdf_path') or '-'}")
        print(f"XLSX report: {report.get('xlsx_path', '-')}")
        print(f"Unique findings: {report['report']['unique_findings']}")
        print(f"Raw observations: {report['report']['raw_findings']}")
        print(f"Affected URLs: {report['report'].get('affected_urls', 0)}")

        state.update(
            status="COMPLETE",
            stage="PENTEST COMPLETE",
            detail=("Assessment finished. The HTML report contains the target overview, affected pages, focused evidence and plain-language explanations."
                    + (f" Some phases failed and are listed in the report: {', '.join(phase_failures)}." if phase_failures else "")),
            progress=100,
            findings=report["report"]["unique_findings"],
            checks=(len(ui_result.get("results", [])) + len(active_result.get("checks", []))),
            log={"time": datetime.now().strftime("%H:%M:%S"), "level": "ok",
                 "message": "Pentest complete. Open the generated HTML report."},
        )
        loader.set("Pentest complete")
        return 0
    except Exception as exc:
        phase_status["assessment"] = {
            "status": "failed",
            "error": f"{type(exc).__name__}: {exc}",
        }
        try:
            partial = _refresh_live_report(target, all_findings, current_metadata("PARTIAL"))
            count = partial["report"]["unique_findings"] if partial else len(all_findings)
        except Exception:
            count = len(all_findings)
        state.update(
            status="FAILED",
            stage="ASSESSMENT FAILED",
            detail=f"Assessment stopped unexpectedly, but the partial HTML report was preserved. Error: {type(exc).__name__}: {exc}",
            findings=count,
            log={"time": datetime.now().strftime("%H:%M:%S"), "level": "error",
                 "message": "Assessment stopped. Partial report preserved."},
        )
        loader.set("Assessment failed; partial report preserved")
        return 1
    finally:
        loader.stop()

def run_intrusive_profile(target: str, plan_path: str, authorized: bool = False, confirm_intrusive: bool = False, confirm_destructive: bool = False, dry_run: bool = False):
    """Run explicitly configured, reversible state-changing tests only."""
    if not authorized:
        print("[BLOCKED] Intrusive mode requires --confirm-authorized.")
        return 1
    if not confirm_intrusive:
        print("[BLOCKED] Intrusive mode requires --confirm-intrusive.")
        print("[INFO] Every operation must be configured against a disposable test resource with rollback.")
        return 1
    if not dry_run and not confirm_destructive:
        print("[BLOCKED] Non-dry-run controlled-destructive mode requires --confirm-destructive.")
        print("[INFO] This second gate confirms that configured disposable data may be created, modified and deleted for rollback.")
        return 1
    banner("CONTROLLED INTRUSIVE MODE — EXPLICIT ROLLBACK REQUIRED")
    print("[MODE] Controlled-destructive tests: DISABLED (dry-run)" if dry_run else "[MODE] Controlled-destructive tests: ENABLED")
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
    """Run security-only testing with visible progress and bounded phases."""
    loader = ConsoleLoader()
    loader.start("Initializing security assessment")
    try:
        banner("SECURITY-ONLY MODE — DEEP AUTHORIZED ASSESSMENT")
        print("[MODE] UI/compatibility testing: DISABLED")
        print("[MODE] Browser/Playwright: DISABLED")
        print("[MODE] Security engine: ENABLED")
        print("[MODE] Scope: exact origin of supplied target; redirects disabled")
        print("[MODE] State-changing requests: DISABLED")
        print("[MODE] Credential attacks / DoS / destructive writes: DISABLED")
        print("[MODE] GET / HEAD / OPTIONS / TRACE + controlled header/query probes")
        print(f"[LIMITS] max_urls={max_urls or config.SECURITY_MAX_URLS}, max_probes={max_probes or config.SECURITY_MAX_PROBES}, timeout={config.SECURITY_TIMEOUT}s")

        loader.set("Deep security assessment — progress appears below")
        print("\n[STAGE 1/2] Deep security assessment starting...", flush=True)
        result = run_deep_security(
            target,
            max_urls=max_urls or config.SECURITY_MAX_URLS,
            max_probes=max_probes or config.SECURITY_MAX_PROBES,
        )
        print(f"[STAGE 1/2] Deep security complete: {result['probe_count']} probes, {len(result['findings'])} raw findings.", flush=True)

        banner("PASSIVE ROUTE / API DISCOVERY")
        print("[MODE] GET-only discovery; discovered POST/PUT/PATCH/DELETE routes are inventory candidates.")
        loader.set("Passive route/API discovery — GET only")
        print("[STAGE 2/2] Passive route/API discovery starting...", flush=True)
        api_result = run_api_surface(
            target,
            max_probes=min(config.SECURITY_MAX_PROBES, 100),
        )
        route = api_result.get("route_discovery") or {}
        route_summary = route.get("summary", {})
        print(f"Pages inspected: {route_summary.get('pages', 0)}")
        print(f"JavaScript assets inspected: {route_summary.get('assets', 0)}")
        print(f"Routes discovered: {route_summary.get('routes', 0)}")
        print(f"API-like routes: {route_summary.get('api_like_routes', 0)}")
        print(f"State-changing candidates: {route_summary.get('state_changing_candidates', 0)}")
        print(f"API specifications: {api_result['summary']['specs']}")
        print(f"Documented API endpoints: {api_result['summary']['endpoints']}")
        print(f"Evidence: {config.EVIDENCE_DIR}/discovered_routes.json")
        print(f"API inventory: {config.EVIDENCE_DIR}/api_surface.json")

        banner("DEEP SECURITY ASSESSMENT COMPLETE")
        print(f"URLs tested: {len(result['urls_tested'])}")
        print(f"HTTP probes: {result['probe_count']}")
        print(f"Deep findings: {len(result['findings'])}")
        print(f"API inventory observations: {len(api_result.get('findings', []))}")
        for sev, count in result["summary"]["by_severity"].items():
            print(f"  {sev}: {count}")
        print(f"Evidence: {config.EVIDENCE_DIR}/deep_security.json")
        print(f"Report: {result['report']['html_path']}")
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
    result = generate(target, all_findings, config.EVIDENCE_DIR, out_dir=config.REPORT_DIR)
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
        help="auto selects pentest; intrusive is a legacy alias for the non-destructive full pentest; lab remains available for localhost",
    )
    parser.add_argument("--headed", action="store_true", help="show Chrome/Chromium browser windows during UI testing")
    parser.add_argument("--slow-mo", type=int, default=0, metavar="MS",
                        help="delay each Playwright action by MS milliseconds (e.g. 500)")
    parser.add_argument("--no-dashboard", action="store_true",
                        help="disable the local visual dashboard")
    parser.add_argument("--confirm-authorized", action="store_true",
                        help="confirm that you own the target or have explicit authorization for arbitrary-target pentesting")
    parser.add_argument("--confirm-intrusive", action="store_true",
                        help="legacy compatibility flag; ignored by the non-destructive intrusive alias")
    parser.add_argument("--confirm-destructive", action="store_true",
                        help="legacy compatibility flag; ignored by the non-destructive intrusive alias")
    parser.add_argument("--intrusive-plan", default="intrusive_plan.json",
                        help="legacy compatibility option; not used by the non-destructive intrusive alias")
    parser.add_argument("--dry-run", action="store_true", help="legacy compatibility option; not used by the non-destructive intrusive alias")
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
            print("[NOTE] 'intrusive' is now a compatibility alias for the non-destructive full pentest.")
            print("[NOTE] No state-changing requests, destructive plan, or rollback actions are executed.")
            return run_pentest_profile(
                target,
                headed=args.headed,
                slow_mo=args.slow_mo,
                dashboard=not args.no_dashboard,
                authorized=args.confirm_authorized,
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
