#!/usr/bin/env python3
"""Phase 7 authenticated HTTP-method differential assessment."""
import argparse
import json
import os

import config
from scanners.authenticated_method_diff import compare_methods, login_with_env


def main():
    p = argparse.ArgumentParser(description="Phase 7 authenticated HTTP-method differential assessment")
    p.add_argument("--target", default=config.DEFAULT_TARGET)
    p.add_argument("--confirm-authorized", action="store_true")
    p.add_argument("--login-path", default="/login")
    p.add_argument("--account-a-user-env", default="SENTINEL_TEST_A_USER")
    p.add_argument("--account-a-pass-env", default="SENTINEL_TEST_A_PASS")
    p.add_argument("--account-b-user-env", default="SENTINEL_TEST_B_USER")
    p.add_argument("--account-b-pass-env", default="SENTINEL_TEST_B_PASS")
    p.add_argument("--endpoint", required=True, help="Endpoint containing {id}, e.g. /api/orders/{id}")
    p.add_argument("--object-a", required=True)
    p.add_argument("--object-b", required=True)
    args = p.parse_args()

    if not args.confirm_authorized and args.target.rstrip("/") != config.PENTEST_TARGET_ORIGIN.rstrip("/"):
        raise SystemExit("Arbitrary Phase 7 targets require --confirm-authorized.")

    a = login_with_env(args.target, args.account_a_user_env, args.account_a_pass_env, args.login_path)
    b = login_with_env(args.target, args.account_b_user_env, args.account_b_pass_env, args.login_path)
    result = compare_methods(a, b, args.target, args.endpoint, args.object_a, args.object_b)

    os.makedirs(config.EVIDENCE_DIR, exist_ok=True)
    path = os.path.join(config.EVIDENCE_DIR, "phase7_method_diff.json")
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(result, handle, indent=2, ensure_ascii=False)

    print(f"Evidence: {path}")
    print(f"HEAD A -> B: {result['head_authorization_bypass']['a_to_b']}")
    print(f"HEAD B -> A: {result['head_authorization_bypass']['b_to_a']}")
    print(f"OPTIONS observations: {len(result['observations'])}")
    print(f"Findings: {len(result['findings'])}")


if __name__ == "__main__":
    raise SystemExit(main())
