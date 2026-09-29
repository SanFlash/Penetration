#!/usr/bin/env python3
"""Explicitly gated controlled state-change assessment CLI.

Only configured disposable resources are eligible. The existing intrusive
validator enforces exact-origin scope, rollback requirements, bounded action
count and disallows standalone DELETE actions.
"""
import argparse

import config
from scanners.intrusive import run_intrusive


def main():
    parser = argparse.ArgumentParser(description="Controlled disposable-resource assessment")
    parser.add_argument("--target", required=True)
    parser.add_argument("--plan", default="intrusive_plan.json")
    parser.add_argument("--confirm-authorized", action="store_true")
    parser.add_argument("--confirm-intrusive", action="store_true")
    parser.add_argument("--confirm-destructive", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    if not args.confirm_authorized:
        print("[BLOCKED] Requires --confirm-authorized.")
        return 1
    if not args.confirm_intrusive:
        print("[BLOCKED] Requires --confirm-intrusive.")
        return 1
    if not args.dry_run and not args.confirm_destructive:
        print("[BLOCKED] Non-dry-run requires --confirm-destructive.")
        return 1

    print("[PROFILE] controlled-disposable")
    print("[MODE] Only explicitly configured disposable resources")
    print("[MODE] Every state-changing action must have rollback")
    print("[MODE] Exact target origin; redirects disabled; max actions enforced")
    print(f"[MODE] Dry run: {'YES' if args.dry_run else 'NO'}")

    try:
        result = run_intrusive(
            args.target,
            args.plan,
            timeout=config.INTRUSIVE_TIMEOUT,
            dry_run=args.dry_run,
        )
    except (FileNotFoundError, ValueError) as exc:
        print(f"[ERROR] Plan rejected: {exc}")
        return 2

    summary = result["summary"]
    print(f"Actions: {summary['actions']}")
    print(f"Action failures: {summary['action_failures']}")
    print(f"Rollbacks OK: {summary['rollbacks_ok']}")
    print(f"Failed rollbacks: {summary['failed_rollbacks']}")
    print("Evidence: evidence/intrusive_security.json")

    if summary["failed_rollbacks"]:
        print("[STOP] Restore the disposable resource manually before continuing.")
        return 3
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
