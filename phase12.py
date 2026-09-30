#!/usr/bin/env python3
import argparse,sys
from pathlib import Path
from scanners.phase12_aggressive_api_matrix import run_phase12
from utils.scope import assert_same_target,OutOfScopeError

def main():
    p=argparse.ArgumentParser(description="Authorized Phase 12 authenticated API matrix")
    p.add_argument("--target",required=True); p.add_argument("--endpoint",action="append",required=True)
    p.add_argument("--login-path",default="/login")
    p.add_argument("--user-a-env",default="SENTINEL_TEST_A_USER"); p.add_argument("--pass-a-env",default="SENTINEL_TEST_A_PASS")
    p.add_argument("--user-b-env",default="SENTINEL_TEST_B_USER"); p.add_argument("--pass-b-env",default="SENTINEL_TEST_B_PASS")
    p.add_argument("--object-endpoint"); p.add_argument("--object-a"); p.add_argument("--object-b")
    p.add_argument("--max-probes",type=int,default=80); p.add_argument("--evidence-dir",default="evidence")
    p.add_argument("--confirm-authorized",action="store_true"); a=p.parse_args(); target=a.target.rstrip("/")
    if not a.confirm_authorized: print("[BLOCKED] Phase 12 requires --confirm-authorized."); return 1
    for e in a.endpoint:
        try: assert_same_target(target,target+e)
        except OutOfScopeError as exc: print(f"[BLOCKED] {exc}"); return 1
    if a.object_endpoint and (a.object_a is None or a.object_b is None): p.error("--object-endpoint requires --object-a and --object-b")
    try:
        r=run_phase12(target,a.endpoint,a.login_path,a.user_a_env,a.pass_a_env,a.user_b_env,a.pass_b_env,
                      a.object_endpoint,a.object_a,a.object_b,a.max_probes,a.evidence_dir)
    except (RuntimeError,ValueError,OSError) as exc: print(f"[ERROR] {exc}"); return 2
    s=r["summary"]; print("\nPHASE 12 — AGGRESSIVE AUTHENTICATED API MATRIX")
    print(f"Endpoints tested: {s['endpoints_tested']}"); print(f"Read-only probes: {s['probes']}")
    print(f"BOLA tested: {'YES' if s['bola_tested'] else 'NO'}"); print(f"Findings: {s['findings']}")
    print(f"Evidence: {Path(a.evidence_dir)/'phase12_aggressive_api_matrix.json'}"); return 0
if __name__=="__main__": sys.exit(main())
