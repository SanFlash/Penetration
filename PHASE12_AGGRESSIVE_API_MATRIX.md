# Phase 12 — Aggressive Authenticated API Matrix

This phase increases depth while remaining controlled and read-only against application data.

Coverage:
- authenticated and unauthenticated GET/HEAD/OPTIONS differential checks
- explicit same-origin API endpoint inventory
- bounded malformed/boundary query-parameter testing
- response fingerprints and JSON response-shape comparison
- authentication-boundary signals
- optional two-account BOLA/IDOR checks using disposable object IDs
- evidence redaction for credential-like query parameters

Safety:
- requires --confirm-authorized
- exact same-origin enforcement
- redirects disabled
- bounded probe budget
- only the login POST is state-changing
- no credential brute force, DoS, persistence, command execution, or arbitrary writes
- do not automatically invoke POST/PUT/PATCH/DELETE API routes

Example:
python phase12.py --target http://127.0.0.1:5000 --confirm-authorized --endpoint "/api/orders/1" --endpoint "/api/orders/2" --object-endpoint "/api/orders/{id}" --object-a 1 --object-b 2

Use disposable test objects/accounts. A finding remains a review signal unless the endpoint's authorization contract establishes that the compared object must be inaccessible.
