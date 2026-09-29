#!/usr/bin/env python3
"""Standalone comprehensive authorized web assessment CLI.

This mode is read-only and intentionally broader than the normal pentest
profile. It adds common exposed-resource, cookie, header, diagnostic and
HTTP-method checks while keeping strict same-origin, rate and probe limits.
"""
import argparse

import config
from scanners.comprehensive_security import run_comprehensive_security
from reports.report_generator import generate


def main():
    parser = argparse.ArgumentParser(description="Comprehensive authorized web security assessment")
    parser.add_argument("--target", required=True, help="Authorized HTTP(S) origin")
    parser.add_argument("--max-urls", type=int, default=getattr(config, "COMPREHENSIVE_MAX_URLS", 80))
    parser.add_argument("--max-probes", type=int, default=getattr(config, "COMPREHENSIVE_MAX_PROBES", 260))
    parser.add_argument("--confirm-authorized", action="store_true",
                        help="confirm ownership or explicit authorization")
    args = parser.parse_args()

    if not args.confirm_authorized:
        print("[BLOCKED] Comprehensive assessment requires --confirm-authorized.")
        return 1

    print("[PROFILE] comprehensive")
    print("[MODE] Broad read-only security assessment")
    print("[MODE] GET/OPTIONS only | same-origin | redirects disabled")
    print("[MODE] No form submission, uploads, writes, deletes, credential attacks or DoS")

    result = run_comprehensive_security(
        args.target,
        max_urls=args.max_urls,
        max_probes=args.max_probes,
    )
    report = generate(
        args.target,
        result["findings"],
        config.EVIDENCE_DIR,
        metadata={
            "profile": "comprehensive",
            "methodology": "OWASP WSTG-aligned comprehensive read-only assessment",
            "comprehensive_security": result,
        },
    )

    print("\nCOMPREHENSIVE ASSESSMENT COMPLETE")
    print(f"Probes: {result['probes']}")
    print(f"Findings: {len(result['findings'])}")
    print(f"Findings JSON: {report['json_path']}")
    print(f"Findings HTML: {report['html_path']}")
    for severity, count in report["report"]["severity_summary"].items():
        if count:
            print(f"  {severity}: {count}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
