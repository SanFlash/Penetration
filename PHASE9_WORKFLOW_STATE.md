# Phase 9 — Authenticated Workflow State / Precondition Assessment

Phase 9 checks whether a selected business action is exposed only in the correct server-side workflow state.

## What it tests

The operator supplies:
- a read-only endpoint containing `{id}` and `{action}`
- two disposable object IDs
- the known server-side state of each object
- one explicitly authorized workflow action
- the expected authorization decision for each state

The scanner performs exactly two authenticated GET requests.
It does not attempt to change an object's state.

## Example

For a workflow where `cancel` is valid only while an order is `pending`:
- object 1: `pending` -> expected allowed `true`
- object 3: `completed` -> expected allowed `false`

```powershell
python phase9.py --target http://127.0.0.1:5000 --confirm-authorized --endpoint "/api/orders/{id}/workflow/{action}" --object-a "1" --object-b "3" --state-a "pending" --state-b "completed" --action "cancel" --expected-a-allowed true --expected-b-allowed false
```

Protected counterpart:

```powershell
python phase9.py --target http://127.0.0.1:5000 --confirm-authorized --endpoint "/api/orders-secure/{id}/workflow/{action}" --object-a "1" --object-b "3" --state-a "pending" --state-b "completed" --action "cancel" --expected-a-allowed true --expected-b-allowed false
```

Expected vulnerable result: state A allowed, state B incorrectly allowed, one finding.
Expected protected result: state A allowed, state B denied, zero findings.

## Safety
- GET-only workflow requests.
- No state transition is attempted.
- No POST/PUT/PATCH/DELETE workflow request.
- No automatic discovery.
- Same-origin enforcement.
- Redirects disabled.
- One authenticated disposable account.
- Credentials remain in environment variables.
- Expected state and decision values are explicitly supplied by the operator.

Evidence: `evidence/phase9_workflow_state.json`