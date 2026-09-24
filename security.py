#!/usr/bin/env python3
"""Dedicated security-only command for authorized deep web assessment.

Example:
    python security.py --target https://amwebtech.com
"""
import argparse
import sys

import config
from scanners.deep_security import run_deep_security
from utils.scope import assert_in_scope, assert_same_target, OutOfScopeError


def main():
    parser = argparse.ArgumentParser(
        description="Sentinel Deep Security — security-only authorized assessment"
    )
    parser.add_argument("--target", default=config.PENTEST_TARGET_ORIGIN)
    parser.add_argument("--max-urls", type=int, default=config.SECURITY_MAX_URLS)
    parser.add_argument("--max-probes", type=int, default=config.SECURITY_MAX_PROBES)
    args = parser.parse_args()

    target = args.target.rstrip("/")
    if args.max_urls < 1 or args.max_urls > 200:
        parser.error("--max-urls must be between 1 and 200")
    if args.max_probes < 1 or args.max_probes > 1000:
        parser.error("--max-probes must be between 1 and 1000")

    try:
        assert_in_scope(target + "/")
        assert_same_target(config.PENTEST_TARGET_ORIGIN, target)
    except OutOfScopeError as exc:
        print(f"[BLOCKED] {exc}")
        return 1

    print("=" * 78)
    print("SENTINEL DEEP SECURITY — SECURITY-ONLY MODE")
    print("=" * 78)
    print(f"Target:       {target}")
    print(f"Max URLs:     {args.max_urls}")
    print(f"Max probes:   {args.max_probes}")
    print("Browser/UI:   DISABLED")
    print("Writes:       DISABLED")
    print("DoS/bruteforce: DISABLED")
    print("=" * 78)

    try:
        result = run_deep_security(
            target,
            max_urls=args.max_urls,
            max_probes=args.max_probes,
        )
    except KeyboardInterrupt:
        print("\n[STOPPED] Assessment interrupted.")
        return 130
    except Exception as exc:
        print(f"\n[ERROR] Security assessment failed: {exc}")
        return 2

    print("\n" + "=" * 78)
    print("DEEP SECURITY COMPLETE")
    print("=" * 78)
    print(f"URLs tested:  {len(result['urls_tested'])}")
    print(f"HTTP probes:  {result['probe_count']}")
    print(f"Findings:     {len(result['findings'])}")
    print(f"Evidence:     {config.EVIDENCE_DIR}/deep_security.json")
    print(f"Report:       {result['report']['html_path']}")
    print("=" * 78)
    return 0


if __name__ == "__main__":
    sys.exit(main())
