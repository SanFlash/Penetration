#!/usr/bin/env python3
"""Phase 9 authenticated workflow-state/precondition assessment."""
import argparse
import json
import os

import config
from scanners.workflow_state_preconditions import assess_workflow_preconditions, login_with_env


def _bool(value: str) -> bool:
    normalized = value.strip().lower()
    if normalized in {"true", "1", "yes", "allow", "allowed"}:
        return True
    if normalized in {"false", "0", "no", "deny", "denied"}:
        return False
    raise argparse.ArgumentTypeError("expected true or false")


def main():
    p = argparse.ArgumentParser(
        description="Phase 9 authenticated workflow-state/precondition assessment"
    )
    p.add_argument("--target", default=config.DEFAULT_TARGET)
    p.add_argument("--confirm-authorized", action="store_true")
    p.add_argument("--login-path", default="/login")
    p.add_argument("--user-env", default="SENTINEL_TEST_A_USER")
    p.add_argument("--pass-env", default="SENTINEL_TEST_A_PASS")
    p.add_argument("--endpoint", required=True, help="Read-only action endpoint containing {id} and {action}")
    p.add_argument("--object-a", required=True)
    p.add_argument("--object-b", required=True)
    p.add_argument("--state-a", required=True, help="Known server-side state for object A")
    p.add_argument("--state-b", required=True, help="Known server-side state for object B")
    p.add_argument("--action", required=True)
    p.add_argument("--expected-a-allowed", required=True, type=_bool)
    p.add_argument("--expected-b-allowed", required=True, type=_bool)
    args = p.parse_args()

    if not args.confirm_authorized and args.target.rstrip("/") != config.PENTEST_TARGET_ORIGIN.rstrip("/"):
        raise SystemExit("Arbitrary Phase 9 targets require --confirm-authorized.")

    session = login_with_env(
        args.target, args.user_env, args.pass_env, args.login_path
    )
    result = assess_workflow_preconditions(
        session,
        args.target,
        args.endpoint,
        args.object_a,
        args.object_b,
        args.action,
        args.expected_a_allowed,
        args.expected_b_allowed,
        args.state_a,
        args.state_b,
    )

    os.makedirs(config.EVIDENCE_DIR, exist_ok=True)
    path = os.path.join(config.EVIDENCE_DIR, "phase9_workflow_state.json")
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(result, handle, indent=2, ensure_ascii=False)

    print(f"Evidence: {path}")
    for key in ("state_a", "state_b"):
        row = result["responses"][key]
        print(
            f"{key}: state={row['workflow_state']} "
            f"expected={row['expected_allowed']} "
            f"observed={row['observed_allowed']}"
        )
    print(f"State mismatches: {len(result['mismatches'])}")
    print(f"Findings: {len(result['findings'])}")


if __name__ == "__main__":
    raise SystemExit(main())
