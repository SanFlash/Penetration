#!/usr/bin/env python3
"""Phase 5 authenticated API/route discovery."""
import argparse
import json
import os

import config
from scanners.authenticated_api_discovery import (
    DEFAULT_MAX_CANDIDATES,
    DEFAULT_MAX_PAGES,
    DEFAULT_MAX_RUNTIME,
    DEFAULT_TIMEOUT,
    discover_authenticated,
    login_with_env,
)


def main():
    p = argparse.ArgumentParser(description="Phase 5 authenticated API/route discovery")
    p.add_argument("--target", default=config.DEFAULT_TARGET)
    p.add_argument("--confirm-authorized", action="store_true")
    p.add_argument("--login-path", default="/login")
    p.add_argument("--start-path", action="append", default=["/"])
    p.add_argument("--account-user-env", default="SENTINEL_TEST_A_USER")
    p.add_argument("--account-pass-env", default="SENTINEL_TEST_A_PASS")
    p.add_argument("--max-pages", type=int, default=DEFAULT_MAX_PAGES)
    p.add_argument("--max-candidates", type=int, default=DEFAULT_MAX_CANDIDATES)
    p.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT)
    p.add_argument("--max-runtime", type=int, default=DEFAULT_MAX_RUNTIME)
    args = p.parse_args()

    if not args.confirm_authorized and args.target.rstrip("/") != config.PENTEST_TARGET_ORIGIN.rstrip("/"):
        raise SystemExit("Arbitrary Phase 5 targets require --confirm-authorized.")
    session = login_with_env(
        args.target, args.account_user_env, args.account_pass_env, args.login_path
    )
    result = discover_authenticated(
        session,
        args.target,
        args.start_path,
        args.max_pages,
        args.max_candidates,
        args.timeout,
        args.max_runtime,
    )
    os.makedirs(config.EVIDENCE_DIR, exist_ok=True)
    path = os.path.join(config.EVIDENCE_DIR, "phase5_authenticated_api.json")
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(result, handle, indent=2, ensure_ascii=False)
    api_like = sum(1 for item in result["candidates"] if item["kind"] == "api-like")
    print(f"Evidence: {path}")
    print(f"Authenticated pages: {result['pages_fetched']}")
    print(f"Candidates: {len(result['candidates'])}")
    print(f"API-like candidates: {api_like}")
    print("No candidate endpoints were invoked automatically.")


if __name__ == "__main__":
    raise SystemExit(main())
