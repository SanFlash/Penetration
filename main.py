#!/usr/bin/env python3
"""CLI orchestrator for the authorized web pentest framework.

Pipeline: scope check -> HTTP recon -> authenticated Playwright recon ->
security headers -> reflected XSS -> SQLi -> IDOR/control test -> report.
"""
import argparse
import sys
import time

import config
from utils.scope import assert_in_scope, OutOfScopeError
from utils.http_client import TargetConnectionError
from recon.crawler import SafeCrawler
from recon.playwright_recon import authenticated_recon
from scanners import headers as header_scanner
from scanners import xss_probe, sqli_probe, idor_probe
from auth.session import login
from reports.report_generator import generate


def banner(text):
    print("\n" + "=" * 70)
    print(text)
    print("=" * 70)


def main():
    parser = argparse.ArgumentParser(description="Authorized web pentest framework")
    parser.add_argument(
        "--target",
        default=config.DEFAULT_TARGET,
        help="Base URL of an IN-SCOPE target (see config.ALLOWED_HOSTS)",
    )
    args = parser.parse_args()
    target = args.target.rstrip("/")

    banner("STEP 0 — Scope check")
    try:
        assert_in_scope(target + "/")
    except OutOfScopeError as exc:
        print(f"[BLOCKED] {exc}")
        return 1

    print(f"[OK] '{target}' is in config.ALLOWED_HOSTS — proceeding.")

    all_findings = []
    start = time.time()

    try:
        banner("STEP 1 — Reconnaissance (scope-limited crawler)")
        crawler = SafeCrawler(target)
        recon_result = crawler.crawl()
        print(
            f"Discovered {len(recon_result['pages'])} pages, "
            f"{len(recon_result['forms'])} forms."
        )
        for pg in recon_result["pages"]:
            print(f"  {pg['status']}  {pg['url']}")

        banner("STEP 2 — Authenticated recon (Playwright)")
        pw_result = authenticated_recon(
            target, config.DEMO_USERNAME, config.DEMO_PASSWORD
        )
        print(f"Observed {pw_result['total_requests_observed']} network requests.")
        print(f"API-shaped endpoints found: {pw_result['api_endpoints']}")
        for c in pw_result["cookies"]:
            flag_note = "OK" if c["httpOnly"] else "MISSING HttpOnly"
            print(
                f"  cookie '{c['name']}': httpOnly={c['httpOnly']} "
                f"secure={c['secure']} -> {flag_note}"
            )
            if not c["httpOnly"]:
                all_findings.append({
                    "id": f"COOKIE-{c['name']}",
                    "title": f"Session cookie '{c['name']}' missing HttpOnly flag",
                    "severity": "Medium",
                    "confidence": "High",
                    "category": "Session Management",
                    "url": target,
                    "detail": "A cookie without HttpOnly is readable by JavaScript, "
                              "widening the impact of any XSS finding.",
                    "remediation": "Set the HttpOnly attribute on session cookies.",
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
        print(
            f"Error-based signal: {sqli_result['error_triggered']}  "
            f"Boolean-based signal: {sqli_result['boolean_diff']}"
        )
        all_findings.extend(sqli_result["findings"])

        banner("STEP 6 — IDOR probe on /api/orders/{id}")
        session = login(target, config.DEMO_USERNAME, config.DEMO_PASSWORD)
        idor_result = idor_probe.probe_endpoint(
            session, target, "/api/orders/{id}", owned_id=2, other_id=1
        )
        print(
            f"Own order (id=2) status: {idor_result['owned_status']}  "
            f"Other user's order (id=1) status: {idor_result['other_status']}  "
            f"Vulnerable: {idor_result['vulnerable']}"
        )
        all_findings.extend(idor_result["findings"])

        banner("STEP 6b — Same probe against the SECURE endpoint (control test)")
        idor_secure_result = idor_probe.probe_endpoint(
            session, target, "/api/orders-secure/{id}", owned_id=2, other_id=1
        )
        print(
            f"Own order (id=2) status: {idor_secure_result['owned_status']}  "
            f"Other user's order (id=1) status: {idor_secure_result['other_status']}  "
            f"Vulnerable: {idor_secure_result['vulnerable']}"
        )
        if idor_secure_result["vulnerable"]:
            print("  [UNEXPECTED] secure control endpoint was flagged.")
        else:
            print("  [OK] scanner correctly did NOT flag the secure control endpoint.")

        banner("STEP 7 — Report generation")
        result = generate(target, all_findings, config.EVIDENCE_DIR)
        elapsed = round(time.time() - start, 1)
        print(f"Findings JSON: {result['json_path']}")
        print(f"Findings HTML: {result['html_path']}")
        print(
            f"Total findings: {result['report']['total_findings']} "
            f"(run completed in {elapsed}s)"
        )

        banner("SUMMARY")
        for sev, count in result["report"]["severity_summary"].items():
            if count:
                print(f"  {sev}: {count}")
        return 0

    except TargetConnectionError as exc:
        print("\n[ERROR] Target is unreachable.")
        print(f"  Target: {exc.url}")
        print("  Check that the authorized target is running and the host/port is correct.")
        print("  Local lab: python demo_target/app.py")
        return 2
    except KeyboardInterrupt:
        print("\n[STOPPED] Scan interrupted by user.")
        return 130


if __name__ == "__main__":
    sys.exit(main())
