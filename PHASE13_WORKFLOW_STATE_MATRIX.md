# Phase 13 — Workflow State / Action Matrix

Read-only authenticated testing of explicit workflow decision endpoints.

## What it adds
- Multiple business actions tested against two known disposable workflow states
- Expected-vs-observed authorization decisions
- State differential analysis
- Detection of workflow authorization mismatches
- Detection when distinct expected states collapse to the same authorization decision
- JSON evidence and bounded probe budgets

## Example
\`python phase13.py --target http://127.0.0.1:5000 --confirm-authorized --endpoint "/api/orders/{id}/workflow/{action}" --object-a 1 --object-b 2 --case "cancel:true:false:pending:completed"\`

Only GET requests are made after login. The framework never attempts to transition an object between states.
