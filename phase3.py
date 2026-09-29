#!/usr/bin/env python3
"""CLI entry point for Phase 3 controlled aggressive read-only assessment."""

import argparse
import os
from urllib.parse import urlparse

import config
from recon.crawler import SafeCrawler
from scanners.aggressive_readonly import run_aggressive_readonly
from reports.report_generator import generate


def main():
    parser = argparse.ArgumentParser(description="Phase 3 aggressive read-only authorized assessment")
    parser.add_argument("--target", default=config.DEFAULT_TARGET)
    parser.add_argument("--confirm-authorized", action="store_true")
    parser.add_argument("--max-urls", type=int, default=30)
    parser.add_argument("--max-probes", type=int, default=220)
    args = parser.parse_args()

    parsed = urlparse(args.target)
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.netloc:
        raise SystemExit("Target must be an absolute HTTP(S) URL.")
    if not args.confirm_authorized and args.target.rstrip("/") != config.PENTEST_TARGET_ORIGIN.rstrip("/"):
        raise SystemExit("Arbitrary Phase 3 targets require --confirm-authorized.")

    print("=" * 74)
    print("PHASE 3 — CONTROLLED AGGRESSIVE READ-ONLY ASSESSMENT")
    print("=" * 74)
    print(f"Target: {args.target}")
    print("Safety: same-origin GET only; bounded probes; no form submission; no state changes.")

    crawler = SafeCrawler(args.target, max_pages=min(max(args.max_urls, 1), 60))
    recon = crawler.crawl()
    urls = [page["url"] for page in recon.get("pages", [])]
    print(f"Discovered pages: {len(urls)}")

    result = run_aggressive_readonly(args.target, urls, max_urls=args.max_urls, max_probes=args.max_probes)

    report = generate(
        args.target,
        result["findings"],
        config.EVIDENCE_DIR,
        metadata={
            "profile": "phase3-aggressive-readonly",
            "policy": result["policy"],
            "limits": result["limits"],
            "phase3": result,
        },
    )
    print(f"Evidence: {os.path.join(config.EVIDENCE_DIR, 'phase3_aggressive_readonly.json')}")
    print(f"Findings JSON: {report['json_path']}")
    print(f"Findings HTML: {report['html_path']}")
    print(f"Probes: {result['probes']}")
    print(f"Findings: {report['report']['total_findings']}")
    print("=" * 74)
    print("PHASE 3 COMPLETE")
    print("=" * 74)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
