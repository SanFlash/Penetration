# Hosted Console v2 — Preflight and Coverage Contract

## What changed

- The hosted console performs a server-side preflight request before submitting an assessment.
- Target URLs are parsed as absolute HTTP(S) URLs, malformed ports and credentials are rejected, query strings/fragments are rejected, and default ports/host casing are normalized.
- The API uses a shared profile allow-list and publishes profile-to-engine capability metadata at `GET /api/preflight`.
- The preflight response reports whether the required ZAP environment values exist. This is configuration presence only, not proof that the API is reachable or that its context scope is correct.
- Access-token comparison uses constant-time comparison.
- UI profile descriptions state what is and is not included; they do not imply ZAP findings are merged into Full Pentest.

## Preflight API

```http
GET /api/preflight?target=https%3A%2F%2Fstaging.example.com&profile=pentest
```

The endpoint validates syntax and reports the normalized target, origin, profile capabilities, integration prerequisites, and authorization caveat. It does not start scanning or establish target ownership.

## Security and coverage boundaries

The authorization checkbox is an explicit operator confirmation, not independent proof of permission. Existing scanner-level scope controls remain necessary. The Full Pentest profile runs the built-in multi-engine pipeline; the optional ZAP baseline is a separate profile and its results are not automatically merged into the Full Pentest report. Authenticated role-based authorization, business logic, server-side logging, source dependency auditing, and full WCAG conformance still require the appropriate credentials, test plans, source artifacts, or manual review.

## Regression tests

Run `python -m pytest tests/test_hosted_console_v2.py -q`.
