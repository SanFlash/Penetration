#!/usr/bin/env python3
"""Phase 8 authenticated business-workflow authorization assessment."""
import argparse
import json
import os

import config
from scanners.authenticated_workflow_auth import compare_workflow_action, login_with_env


def main():
    p = argparse.ArgumentParser(description="Phase 8 authenticated business-workflow authorization assessment")
    p.add_argument("--target", default=config.DEFAULT_TARGET)
    p.add_argument("--confirm-authorized", action="store_true")
    p.add_argument("--login-path", default="/login")
    p.add_argument("--account-a-user-env", default="SENTINEL_TEST_A_USER")
    p.add_argument("--account-a-pass-env", default="SENTINEL_TEST_A_PASS")
    p.add_argument("--account-b-user-env", default="SENTINEL_TEST_B_USER")
    p.add_argument("--account-b-pass-env", default="SENTINEL_TEST_B_PASS")
    p.add_argument("--endpoint", required=True, help="Read-only action endpoint containing {id} and {action}")
    p.add_argument("--object-a", required=True)
    p.add_argument("--object-b", required=True)
    p.add_argument("--action", required=True, help="One explicitly authorized disposable workflow action")
    args = p.parse_args()

    if not args.confirm_authorized and args.target.rstrip("/") != config.PENTEST_TARGET_ORIGIN.rstrip("/"):
        raise SystemExit("Arbitrary Phase 8 targets require --confirm-authorized.")

    a = login_with_env(args.target, args.account_a_user_env, args.account_a_pass_env, args.login_path)
    b = login_with_env(args.target, args.account_b_user_env, args.account_b_pass_env, args.login_path)
    result = compare_workflow_action(
        a, b, args.target, args.endpoint, args.object_a, args.object_b, args.action
    )

    os.makedirs(config.EVIDENCE_DIR, exist_ok=True)
    path = os.path.join(config.EVIDENCE_DIR, "phase8_workflow_auth.json")
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(result, handle, indent=2, ensure_ascii=False)

    print(f"Evidence: {path}")
    print(f"A -> B: {result['cross_account_match']['a_to_b']}")
    print(f"B -> A: {result['cross_account_match']['b_to_a']}")
    print(f"Findings: {len(result['findings'])}")


if __name__ == "__main__":
    raise SystemExit(main())
