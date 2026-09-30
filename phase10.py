#!/usr/bin/env python3
import argparse, json, os
import config
from scanners.authz_correlation import assess_correlation, login_with_env

def main():
    p=argparse.ArgumentParser(description="Phase 10 authenticated authorization correlation assessment")
    p.add_argument("--target", default=config.DEFAULT_TARGET); p.add_argument("--confirm-authorized", action="store_true")
    p.add_argument("--login-path", default="/login")
    p.add_argument("--account-a-user-env", default="SENTINEL_TEST_A_USER"); p.add_argument("--account-a-pass-env", default="SENTINEL_TEST_A_PASS")
    p.add_argument("--account-b-user-env", default="SENTINEL_TEST_B_USER"); p.add_argument("--account-b-pass-env", default="SENTINEL_TEST_B_PASS")
    p.add_argument("--endpoint", required=True); p.add_argument("--object-a", required=True); p.add_argument("--object-b", required=True)
    p.add_argument("--owner-a", required=True); p.add_argument("--owner-b", required=True); p.add_argument("--action", required=True)
    p.add_argument("--expected-owner-a-allowed", required=True, type=lambda x:x.lower() in {"true","1","yes"})
    p.add_argument("--expected-owner-b-allowed", required=True, type=lambda x:x.lower() in {"true","1","yes"})
    args=p.parse_args()
    if not args.confirm_authorized and args.target.rstrip("/") != config.PENTEST_TARGET_ORIGIN.rstrip("/"):
        raise SystemExit("Arbitrary Phase 10 targets require --confirm-authorized.")
    a=login_with_env(args.target,args.account_a_user_env,args.account_a_pass_env,args.login_path)
    b=login_with_env(args.target,args.account_b_user_env,args.account_b_pass_env,args.login_path)
    result=assess_correlation(a,b,args.target,args.endpoint,args.object_a,args.object_b,args.owner_a,args.owner_b,args.action,args.expected_owner_a_allowed,args.expected_owner_b_allowed)
    os.makedirs(config.EVIDENCE_DIR,exist_ok=True)
    path=os.path.join(config.EVIDENCE_DIR,"phase10_authz_correlation.json")
    with open(path,"w",encoding="utf-8") as h: json.dump(result,h,indent=2,ensure_ascii=False)
    print(f"Evidence: {path}"); print(f"Mismatches: {len(result['mismatches'])}"); print(f"Findings: {len(result['findings'])}")
if __name__=="__main__": raise SystemExit(main())
