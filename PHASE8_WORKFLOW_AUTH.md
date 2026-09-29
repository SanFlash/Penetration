# Phase 8 — Authenticated Business-Workflow Authorization

Phase 8 checks a single explicitly selected, **read-only** workflow-action
decision endpoint using two disposable accounts and two disposable objects.

## What it tests

The operator supplies:
- an endpoint containing `{id}` and `{action}`
- two disposable object IDs
- one explicitly authorized test action

The scanner requests the owning and non-owning object through both authenticated
sessions and compares response fingerprints.

A cross-account match can indicate that the server is authorizing a business
workflow action from client-supplied identifiers without checking the
authenticated principal.

## Safety

- GET-only against the selected workflow-decision endpoint.
- No workflow mutation is performed.
- No automatic route discovery.
- Same-origin enforcement.
- Redirects disabled.
- Two disposable accounts and objects required.
- Credentials stay in environment variables.
- Evidence does not contain credentials.

## Local lab

The repository's local demo includes intentionally vulnerable and protected
read-only workflow-decision endpoints:

`/api/orders/{id}/action/{action}`
`/api/orders-secure/{id}/action/{action}`

Run the demo, set the Phase 4 credentials, then:

```powershell
python phase8.py --target http://127.0.0.1:5000 --confirm-authorized --endpoint "/api/orders/{id}/action/{action}" --object-a "1" --object-b "2" --action "cancel"
```

Protected counterpart:

```powershell
python phase8.py --target http://127.0.0.1:5000 --confirm-authorized --endpoint "/api/orders-secure/{id}/action/{action}" --object-a "1" --object-b "2" --action "cancel"
```

These endpoints only return an authorization decision; they do not cancel,
modify, or delete an order.

Evidence: `evidence/phase8_workflow_auth.json`
