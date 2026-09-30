# Phase 10 — Authenticated Authorization Correlation

Combines explicitly selected identity, object, owner parameter, and workflow action dimensions.

The assessment performs six bounded GET requests using two disposable authenticated accounts and two disposable objects. The operator defines expected decisions; cross-object combinations are expected to be denied.

Safety: GET-only, same-origin, redirects disabled, no automatic discovery, no POST/PUT/PATCH/DELETE after login, no brute force, no state-changing operations, credentials only from environment variables.

Example endpoint:
 /api/orders/{id}/correlate?owner={owner}&action={action}

Evidence: evidence/phase10_authz_correlation.json
