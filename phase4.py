#!/usr/bin/env python3
import argparse, json, os
import config
from scanners.authz_bola import compare_access, login_with_env

def main():
    p = argparse.ArgumentParser(description="Phase 4 authenticated authorization/BOLA assessment")
    p.add_argument("--target", default=config.DEFAULT_TARGET)
    p.add_argument("--confirm-authorized", action="store_true")
    p.add_argument("--login-path", default="/login")
    p.add_argument("--account-a-user-env", default="SENTINEL_TEST_A_USER")
    p.add_argument("--account-a-pass-env", default="SENTINEL_TEST_A_PASS")
    p.add_argument("--account-b-user-env", default="SENTINEL_TEST_B_USER")
    p.add_argument("--account-b-pass-env", default="SENTINEL_TEST_B_PASS")
    p.add_argument("--endpoint", required=True)
    p.add_argument("--object-a", required=True)
    p.add_argument("--object-b", required=True)
    args = p.parse_args()
    if not args.confirm_authorized and args.target.rstrip("/") != config.PENTEST_TARGET_ORIGIN.rstrip("/"):
        raise SystemExit("Arbitrary Phase 4 targets require --confirm-authorized.")
    if args.object_a == args.object_b or not args.endpoint.startswith("/") or "{id}" not in args.endpoint:
        raise SystemExit("Use two different disposable object IDs and an absolute endpoint containing {id}.")
    a = login_with_env(args.target, args.account_a_user_env, args.account_a_pass_env, args.login_path)
    b = login_with_env(args.target, args.account_b_user_env, args.account_b_pass_env, args.login_path)
    result = compare_access(a, b, args.target, args.endpoint, args.object_a, args.object_b)
    os.makedirs(config.EVIDENCE_DIR, exist_ok=True)
    path = os.path.join(config.EVIDENCE_DIR, "phase4_authz_bola.json")
    with open(path, "w", encoding="utf-8") as h: json.dump(result, h, indent=2)
    print(f"Evidence: {path}")
    print(f"A -> B: {result['cross_account_match']['a_to_b']}")
    print(f"B -> A: {result['cross_account_match']['b_to_a']}")
    print(f"Findings: {len(result['findings'])}")

if __name__ == "__main__": raise SystemExit(main())
