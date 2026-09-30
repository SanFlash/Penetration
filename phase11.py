#!/usr/bin/env python3
"""CLI for Phase 11 deep authenticated, API and differential assessment."""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path
from urllib.parse import urlparse

from scanners.phase11_deep_authenticated import run_phase11
from utils.scope import assert_same_target, OutOfScopeError


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Authorized Phase 11 read-only authenticated/API assessment"
    )
    parser.add_argument("--target", required=True)
    parser.add_argument(
        "--endpoint",
        action="append",
        required=True,
        help="Explicit same-origin API path. Repeat for multiple endpoints.",
    )
    parser.add_argument("--login-path", default="/login")
    parser.add_argument("--user-a-env", default="SENTINEL_TEST_A_USER")
    parser.add_argument("--pass-a-env", default="SENTINEL_TEST_A_PASS")
    parser.add_argument("--user-b-env", default="SENTINEL_TEST_B_USER")
    parser.add_argument("--pass-b-env", default="SENTINEL_TEST_B_PASS")
    parser.add_argument("--object-a")
    parser.add_argument("--object-b")
    parser.add_argument("--owner-a")
    parser.add_argument("--owner-b")
    parser.add_argument("--action")
    parser.add_argument("--workflow-endpoint")
    parser.add_argument("--expected-a", type=lambda x: x.lower() == "true", default=True)
    parser.add_argument("--expected-b", type=lambda x: x.lower() == "true", default=True)
    parser.add_argument("--max-probes", type=int, default=160)
    parser.add_argument("--evidence-dir", default="evidence")
    parser.add_argument("--confirm-authorized", action="store_true")
    args = parser.parse_args()

    target = args.target.rstrip("/")
    parsed = urlparse(target)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        parser.error("--target must be an absolute http(s) URL")
    if not args.confirm_authorized:
        print("[BLOCKED] Phase 11 requires --confirm-authorized.")
        print("[INFO] Use this only on a system you own or have explicit authorization to assess.")
        return 1
    for endpoint in args.endpoint:
        if not endpoint.startswith("/"):
            parser.error("--endpoint values must start with '/'")
        try:
            assert_same_target(target, target + endpoint)
        except OutOfScopeError as exc:
            print(f"[BLOCKED] Endpoint outside target origin: {exc}")
            return 1

    try:
        result = run_phase11(
            target,
            args.endpoint,
            args.login_path,
            args.user_a_env,
            args.pass_a_env,
            args.user_b_env,
            args.pass_b_env,
            object_a=args.object_a,
            object_b=args.object_b,
            owner_a=args.owner_a,
            owner_b=args.owner_b,
            action=args.action,
            workflow_endpoint=args.workflow_endpoint,
            expected_a=args.expected_a,
            expected_b=args.expected_b,
            max_probes=args.max_probes,
            evidence_dir=args.evidence_dir,
        )
    except (RuntimeError, ValueError, OSError) as exc:
        print(f"[ERROR] {exc}")
        return 2

    summary = result["summary"]
    print("\nPHASE 11 — DEEP AUTHENTICATED ASSESSMENT")
    print(f"API endpoints tested: {summary['api_endpoints_tested']}")
    print(f"Parameter probes: {summary['parameter_probes']}")
    print(f"Method differential endpoints: {summary['method_endpoints']}")
    print(f"BOLA/IDOR tested: {'YES' if summary['bola_tested'] else 'NO'}")
    print(f"Workflow tested: {'YES' if summary['workflow_tested'] else 'NO'}")
    print(f"Findings: {summary['findings']}")
    print(f"Evidence: {Path(args.evidence_dir) / 'phase11_deep_authenticated.json'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
