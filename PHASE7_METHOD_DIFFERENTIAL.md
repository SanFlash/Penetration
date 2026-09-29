# Phase 7 — Authenticated HTTP-Method Differential Assessment

Phase 7 adds a bounded, read-only HTTP-method comparison to the authenticated
authorization test suite.

## Purpose

GET is used as the authorization baseline. HEAD is checked for a potential
authorization bypass because it is read-only. OPTIONS is recorded only as an
exposure observation; an Allow header is not treated as proof that an operation
is authorized.

## Safety boundaries

- Two explicitly authorized disposable test accounts.
- Two explicitly authorized disposable object IDs.
- Operator-selected endpoint; no automatic candidate invocation.
- Same-origin enforcement and redirects disabled.
- Only GET, HEAD, and OPTIONS are sent to the selected endpoint.
- No POST, PUT, PATCH, or DELETE requests are sent by the assessment.
- Credentials come from environment variables and are never written to evidence.

## Usage

PowerShell credentials:

$env:SENTINEL_TEST_A_USER="alice"
$env:SENTINEL_TEST_A_PASS="alice_pw"
$env:SENTINEL_TEST_B_USER="bob"
$env:SENTINEL_TEST_B_PASS="bob_pw"

Example:

python phase7.py --target http://127.0.0.1:5000 --confirm-authorized --endpoint "/api/orders/{id}" --object-a "1" --object-b "2"

Evidence is written to evidence/phase7_method_diff.json.

A finding requires the cross-account GET baseline to be denied while the same
cross-account HEAD request returns HTTP 200. It is a potential bypass and
should be manually validated.

OPTIONS Allow headers are informational only.
