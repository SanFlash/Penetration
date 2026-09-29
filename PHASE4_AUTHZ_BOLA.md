# Phase 4 — Authenticated Authorization / BOLA

Use two explicitly authorized disposable test accounts and two disposable objects.

PowerShell credentials:
    $env:SENTINEL_TEST_A_USER="..."
    $env:SENTINEL_TEST_A_PASS="..."
    $env:SENTINEL_TEST_B_USER="..."
    $env:SENTINEL_TEST_B_PASS="..."

Run:
    python phase4.py --target https://amwebtech.com --confirm-authorized --endpoint /api/items/{id} --object-a TEST_OBJECT_A --object-b TEST_OBJECT_B

Credentials are read only from environment variables and are never written to evidence.
After login, object checks are GET-only. No brute force, creation, modification, or deletion is performed.

A 200 response alone is not treated as proof; bounded response fingerprints are compared between owning and cross-account requests.
