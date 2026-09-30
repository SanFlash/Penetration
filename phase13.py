#!/usr/bin/env python3
import argparse,sys
from pathlib import Path
from scanners.phase13_workflow_state_matrix import run_phase13

def parse_case(v):
    # action:expectedA:expectedB:stateA:stateB
    parts=v.split(":")
    if len(parts)!=5: raise argparse.ArgumentTypeError("case format: action:true:false:stateA:stateB")
    def b(x):
        x=x.lower()
        if x in {"true","1","yes","allow"}: return True
        if x in {"false","0","no","deny"}: return False
        raise argparse.ArgumentTypeError("expected decision must be true/false")
    return parts[0],b(parts[1]),b(parts[2]),parts[3],parts[4]

def main():
    p=argparse.ArgumentParser(description="Phase 13 read-only authenticated workflow state/action matrix")
    p.add_argument("--target",required=True); p.add_argument("--endpoint",required=True)
    p.add_argument("--case",action="append",required=True,type=parse_case,help="action:true:false:stateA:stateB")
    p.add_argument("--object-a",required=True); p.add_argument("--object-b",required=True); p.add_argument("--login-path",default="/login")
    p.add_argument("--user-a-env",default="SENTINEL_TEST_A_USER"); p.add_argument("--pass-a-env",default="SENTINEL_TEST_A_PASS")
    p.add_argument("--user-b-env",default="SENTINEL_TEST_B_USER"); p.add_argument("--pass-b-env",default="SENTINEL_TEST_B_PASS")
    p.add_argument("--max-probes",type=int,default=60); p.add_argument("--evidence-dir",default="evidence"); p.add_argument("--confirm-authorized",action="store_true")
    a=p.parse_args()
    if not a.confirm_authorized: print("[BLOCKED] Phase 13 requires --confirm-authorized."); return 1
    try:r=run_phase13(a.target,a.endpoint,a.case,a.user_a_env,a.pass_a_env,a.user_b_env,a.pass_b_env,a.object_a,a.object_b,a.login_path,a.max_probes,a.evidence_dir)
    except (RuntimeError,ValueError,OSError) as e: print(f"[ERROR] {e}"); return 2
    s=r["summary"]; print("\nPHASE 13 — WORKFLOW STATE/ACTION MATRIX")
    print(f"Actions tested: {s['actions_tested']}"); print(f"Read-only probes: {s['probes']}"); print(f"Findings: {s['findings']}")
    print(f"Evidence: {Path(a.evidence_dir)/'phase13_workflow_state_matrix.json'}"); return 0
if __name__=="__main__":sys.exit(main())
