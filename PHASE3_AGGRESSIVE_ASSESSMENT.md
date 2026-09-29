# Phase 3 — Controlled Aggressive Read-Only Assessment

## Run

For the explicitly authorized AM Webtech target:

    python phase3.py --target https://amwebtech.com --confirm-authorized

Optional bounded controls:

    python phase3.py --target https://amwebtech.com --confirm-authorized --max-urls 30 --max-probes 220

## Coverage

- 11 bounded input payload classes, including a 2 KB boundary value.
- Duplicate query-parameter handling.
- Harmless Accept and Cache-Control header variations.
- 5xx/error-signature detection.
- Exact same-origin enforcement.
- Hard probe, rate and runtime limits.
- Structured evidence and report generation.

## Explicit exclusions

Phase 3 does not perform credential brute force, password spraying, form submission, file uploads, POST/PUT/PATCH/DELETE requests, denial-of-service/flooding, deletion or modification of real records, command execution, or persistence.

State-changing testing remains separately gated and must use disposable resources with rollback.

## Evidence

The scanner writes evidence/phase3_aggressive_readonly.json plus the standard findings JSON and HTML report.
