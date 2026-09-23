# Web Pentest Framework (Python + Playwright)

A small, real, working web-application penetration-testing framework: scope-limited
recon (HTTP crawler + Playwright-driven authenticated browser recon), four scanners
(security headers, reflected XSS, SQL injection, IDOR/BOLA), and JSON/HTML report
generation — all wired together in `main.py`.

## ⚠️ About the target — please read before running anything

**This framework does not, and will not, run against `amwebtech.com` or any other
live third-party site.** It ships configured against a small intentionally-vulnerable
Flask app (`demo_target/app.py`) that this repository builds and runs *locally on
your own machine*, purely so the framework has something real to find.

The framework enforces this itself, in code, not just in this README:

- `config.py` defines `ALLOWED_HOSTS` — an explicit allowlist.
- `utils/scope.py` checks every single outgoing request against that list and
  raises `OutOfScopeError` if the host isn't on it.
- Try it yourself: `python3 main.py --target https://amwebtech.com` — the run
  stops at Step 0 with `[BLOCKED] Refusing to send a request to 'amwebtech.com'...`
  before a single byte is sent.

If you have **written authorization** to test a real target (your own site, or a
client engagement with a signed scope document), add its host to `ALLOWED_HOSTS`
yourself. That is a deliberate, one-line, auditable change — not something this
framework will do implicitly, and not something I built pre-configured for any
specific external domain.

## What's actually in here

```
webpentest-framework/
├── main.py                    # CLI orchestrator — runs the whole pipeline
├── config.py                  # ALLOWED_HOSTS allowlist + settings
├── requirements.txt
├── demo_target/
│   └── app.py                 # intentionally-vulnerable local Flask app (the "lab")
├── recon/
│   ├── crawler.py             # scope-limited HTTP crawler (requests + BeautifulSoup)
│   └── playwright_recon.py    # authenticated, JS-aware recon via a real browser
├── auth/
│   └── session.py             # logs in, returns an authenticated requests.Session
├── scanners/
│   ├── headers.py             # security header presence/absence scanner
│   ├── xss_probe.py           # reflected XSS probe (benign unique marker, not a real payload)
│   ├── sqli_probe.py          # boolean/error-based SQLi probe (non-destructive payloads only)
│   └── idor_probe.py          # horizontal-authorization (IDOR/BOLA) probe
├── reports/
│   └── report_generator.py    # findings.json + a readable report.html
├── utils/
│   ├── scope.py                # the safety control — see above
│   └── http_client.py          # rate-limited, scope-checked, evidence-logging HTTP wrapper
├── evidence/                   # created at runtime: raw requests, screenshots, recon JSON
└── tests/
    └── test_scope.py          # proves scope enforcement actually blocks an out-of-scope host
```

## How it works, end to end

1. **Scope check** (`utils/scope.py`) — the target is checked against `ALLOWED_HOSTS`
   before anything else happens. Fails closed.
2. **Recon — crawler** (`recon/crawler.py`) — a breadth-first crawler that stays on the
   target host, records every page it visits and every `<form>` it finds (action, method,
   input names), so scanners have real endpoints and parameters instead of guesses.
3. **Recon — Playwright** (`recon/playwright_recon.py`) — launches a real headless
   Chromium browser, logs in, and records every network request the *rendered* page
   makes (including JS-driven fetch/XHR calls a plain crawler can't see). Captures
   screenshots as evidence and checks session cookie flags (HttpOnly/Secure).
4. **Header scan** (`scanners/headers.py`) — one GET request, checks for the five
   standard security headers (CSP, HSTS, X-Content-Type-Options, Referrer-Policy,
   Permissions-Policy).
5. **XSS probe** (`scanners/xss_probe.py`) — sends a unique, harmless marker string
   (never a `<script>` payload with real side effects) into a parameter and checks
   whether it's reflected **unescaped** in the response HTML.
6. **SQLi probe** (`scanners/sqli_probe.py`) — sends a single quote (checks for a
   resulting server error) and a true/false pair (checks for a response-length
   difference). No destructive payloads — nothing that writes, alters, or deletes data.
7. **IDOR probe** (`scanners/idor_probe.py`) — as an authenticated user, requests an
   object it owns, then a neighboring object ID it doesn't, and compares the
   authorization outcome. **Also runs the identical probe against a correctly-protected
   endpoint** (`/api/orders-secure/{id}`) as a control, to prove the scanner doesn't
   just flag everything — see the `STEP 6b` output below.
8. **Report** (`reports/report_generator.py`) — collects every finding from every
   step, sorts by severity, and writes both `reports/findings.json` (machine-readable)
   and `reports/report.html` (a self-contained, readable report).

Every HTTP call in the framework goes through `utils/http_client.py`, which enforces
scope, throttles to `config.RATE_LIMIT_RPS` requests/second, and logs the raw
request/response pair to `evidence/raw_requests.jsonl` — so every finding is backed
by reproducible evidence, not just a printed claim.

## Quickstart

```bash
# 1. Install dependencies
pip install -r requirements.txt
playwright install chromium

# 2. Start the local demo target (leave this running in one terminal)
python3 demo_target/app.py
#   -> Serving on http://127.0.0.1:5000 (localhost only)

# 3. In another terminal, run the full framework against it
python3 main.py --target http://127.0.0.1:5000

# 4. Open the report
#    reports/report.html   (open in any browser)
#    reports/findings.json (machine-readable)
#    evidence/              (raw requests, screenshots, recon output)
```

### Proof it actually works — real output from a real run

This is unedited output from running Step 3 onward against `demo_target/app.py`:

```
STEP 4 — Reflected XSS probe on /search?q=
Marker reflected unescaped: True

STEP 5 — SQL injection probe on /products?name=
Error-based signal: True  Boolean-based signal: False

STEP 6 — IDOR probe on /api/orders/{id}
Own order (id=2) status: 200  Other user's order (id=1) status: 200  Vulnerable: True

STEP 6b — Same probe against the SECURE endpoint (control test)
Own order (id=2) status: 200  Other user's order (id=1) status: 403  Vulnerable: False
  [OK] scanner correctly did NOT flag the properly-authorized endpoint.

SUMMARY
  Critical: 1
  High: 2
  Medium: 1
```

Four real findings, against a target that has four real, deliberately-placed
weaknesses — plus a passing control test proving the IDOR scanner doesn't just
rubber-stamp every endpoint as vulnerable.

### Try the scope enforcement yourself

```bash
python3 main.py --target https://amwebtech.com
```
```
STEP 0 — Scope check
[BLOCKED] Refusing to send a request to 'amwebtech.com' — it is not in
config.ALLOWED_HOSTS (['127.0.0.1:5000', 'localhost:5000', '127.0.0.1:3000',
'localhost:3000']). Add it there ONLY if you own it or have written
authorization to test it. See the top of config.py before editing that list.
```

Or run the unit tests directly:
```bash
python3 tests/test_scope.py
# PASS: test_allowed_host_passes
# PASS: test_random_external_host_is_blocked
# PASS: test_assert_in_scope_raises_for_out_of_scope_host
# PASS: test_assert_in_scope_allows_configured_host
```

## Pointing this at a target you're actually authorized to test

1. Confirm you own the target, or have a signed engagement/scope document —
   see the companion "Web Application Penetration Testing" training manual's
   Rules of Engagement chapter for what that document should contain.
2. Add the host to `ALLOWED_HOSTS` in `config.py`:
   ```python
   ALLOWED_HOSTS = [
       "127.0.0.1:5000",
       "staging.yourdomain.com",   # <- your authorized target
   ]
   ```
3. Update `config.DEFAULT_TARGET`, `DEMO_USERNAME`/`DEMO_PASSWORD`, and the
   endpoint paths referenced in `main.py` (`/search`, `/products`, `/api/orders/{id}`,
   the login form field names) to match your target's actual routes and a test
   account provisioned for the engagement — this framework's scanners are generic
   probes, but they still need to be pointed at real parameters and forms, which
   `recon/crawler.py`'s output will help you identify.
4. Lower `RATE_LIMIT_RPS` if the engagement's Rules of Engagement specify a stricter
   ceiling.
5. Re-run `tests/test_scope.py` to confirm the new host is recognized and everything
   else is still blocked.

## What this framework deliberately does NOT do

- No destructive payloads anywhere (no `DROP`/`DELETE`/`UPDATE` SQL, no filesystem
  writes, no account creation floods).
- No automatic target discovery or subdomain enumeration that could wander outside
  an authorized scope.
- No bypassing or disabling of the scope check — there is no `--force` or `--i-know-
  what-im-doing` flag, by design.
- No exploitation beyond what's needed to *prove* a finding (e.g., the XSS probe
  proves reflection with an inert marker; it never executes a real payload).

This mirrors the manual, safe-lab-first methodology taught in the companion
training manual (OWASP WSTG-aligned, NIST SP 800-115-aligned) — this code is
the Part XII "Python Penetration Testing Automation" chapter, actually built out
and proven to run.

## Extending it

- **New scanner**: add a module under `scanners/`, have it call `utils.http_client.get/post`
  (never `requests` directly — that's what enforces scope/rate-limiting/evidence logging),
  and return a dict with a `findings` list in the same shape as the existing scanners.
- **New recon source**: same pattern — always route through `utils/scope.py` before
  touching the network.
- **CI**: `tests/test_scope.py` is plain-Python-runnable and also pytest-compatible
  (`python3 -m pytest tests/ -v`), so it's a one-line addition to any CI pipeline as a
  guardrail against someone accidentally loosening the scope check in a future PR.
