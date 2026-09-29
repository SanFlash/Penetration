# Phase 5 — Authenticated API / Route Discovery

Phase 5 extends the controlled assessment after authentication.

## Purpose

Discover routes and API-like endpoints that are visible only to an authenticated
user, then produce an inventory for later authorization analysis.

## Safety model

- One bounded login request.
- GET-only after authentication.
- Same-origin enforcement.
- Redirects disabled.
- Bounded page/candidate/runtime limits.
- No form submission.
- No POST/PUT/PATCH/DELETE after login.
- Discovered candidates are inventory only and are **not automatically invoked**.
- Credentials are read from environment variables and never written to evidence.

## Demo

Start the repository's local demo target:

```powershell
.\.venv\Scripts\python.exe .\demo_target\app.py
```

Set the demo account:

```powershell
$env:SENTINEL_TEST_A_USER="alice"
$env:SENTINEL_TEST_A_PASS="alice_pw"
```

Run:

```powershell
.\.venv\Scripts\python.exe .\phase5.py --target http://127.0.0.1:5000 --confirm-authorized
```

Evidence is written to:

```text
evidence\phase5_authenticated_api.json
```

The current demo application has very little authenticated route surface, so
a small candidate count is expected. The important result is that the
workflow completes and remains GET-only.

## Production use

Use only an explicitly authorized target and a disposable test account.
Increase limits only when the application's size and runtime justify it.
Review the candidate inventory before any subsequent authenticated security
test. Phase 5 does not automatically mutate or invoke discovered API routes.
