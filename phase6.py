#!/usr/bin/env python3
"""Phase 6 authenticated parameter differential assessment."""
import argparse
import json
import os

import config
from scanners.authenticated_parameter_diff import compare_parameter, login_with_env


def main():
    p = argparse.ArgumentParser(description="Phase 6 authenticated parameter differential assessment")
    p.add_argument("--target", default=config.DEFAULT_TARGET)
    p.add_argument("--confirm-authorized", action="store_true")
    p.add_argument("--login-path", default="/login")
    p.add_argument("--account-a-user-env", default="SENTINEL_TEST_A_USER")
    p.add_argument("--account-a-pass-env", default="SENTINEL_TEST_A_PASS")
    p.add_argument("--account-b-user-env", default="SENTINEL_TEST_B_USER")
    p.add_argument("--account-b-pass-env", default="SENTINEL_TEST_B_PASS")
    p.add_argument("--endpoint", required=True, help="GET endpoint containing {parameter}, e.g. /api/orders?owner={owner}")
    p.add_argument("--parameter", required=True)
    p.add_argument("--value-a", required=True)
    p.add_argument("--value-b", required=True)
    args = p.parse_args()

    if not args.confirm_authorized and args.target.rstrip("/") != config.PENTEST_TARGET_ORIGIN.rstrip("/"):
        raise SystemExit("Arbitrary Phase 6 targets require --confirm-authorized.")

    a = login_with_env(args.target, args.account_a_user_env, args.account_a_pass_env, args.login_path)
    b = login_with_env(args.target, args.account_b_user_env, args.account_b_pass_env, args.login_path)
    result = compare_parameter(
        a, b, args.target, args.endpoint, args.parameter, args.value_a, args.value_b
    )

    os.makedirs(config.EVIDENCE_DIR, exist_ok=True)
    path = os.path.join(config.EVIDENCE_DIR, "phase6_parameter_diff.json")
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(result, handle, indent=2, ensure_ascii=False)

    print(f"Evidence: {path}")
    print(f"A -> B: {result['cross_account_match']['a_to_b']}")
    print(f"B -> A: {result['cross_account_match']['b_to_a']}")
    print(f"Findings: {len(result['findings'])}")


if __name__ == "__main__":
    raise SystemExit(main())
