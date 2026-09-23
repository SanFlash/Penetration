# Web Pentest Framework (Python + Playwright)

A safe-lab-first, scope-limited web-application penetration-testing framework for learning and authorized assessments. It combines HTTP reconnaissance, authenticated Playwright reconnaissance, read-only security probes, evidence collection, and JSON/HTML reporting.

## Authorization and scope

Use this framework only against systems you own or have explicit written authorization to test.

The default configuration targets only the intentionally vulnerable local Flask lab shipped in this repository.

- config.py defines ALLOWED_HOSTS.
- utils/scope.py fails closed when a URL is outside the allowlist.
- There is no --force scope-bypass option.
- The framework does not automatically enumerate arbitrary external targets.
- Probes are designed to be non-destructive.
- Keep the demo target bound to localhost.

## Current capabilities

~~~text
Authorized target
      |
      v
Scope check --------> BLOCK if not explicitly allowed
      |
      v
HTTP crawler
      |
      +-- pages
      +-- forms
      |
      v
Authenticated Playwright recon
      |
      +-- network requests
      +-- API-shaped endpoints
      +-- cookie flags
      +-- screenshots
      |
      v
Read-only scanners
      +-- security headers
      +-- reflected XSS marker
      +-- SQLi detection signals
      +-- IDOR/BOLA authorization comparison
      |
      v
Evidence + structured findings
      |
      v
JSON + HTML assessment report
~~~

### Scanners

- Security headers — checks CSP, HSTS, X-Content-Type-Options, Referrer-Policy, and Permissions-Policy.
- Reflected XSS — uses a unique inert marker rather than a script with side effects.
- SQL injection — uses non-destructive quote and true/false probes. Error and response-shape differences are reported as signals requiring validation, not automatically treated as proof.
- IDOR/BOLA — compares an authenticated user's owned object with a non-owned object and includes a secure control endpoint in the local lab.
- Playwright recon — observes browser-generated network requests and captures screenshots.

## Project structure

~~~text
webpentest-framework/
├── main.py
├── config.py
├── requirements.txt
├── demo_target/
│   └── app.py
├── recon/
│   ├── crawler.py
│   └── playwright_recon.py
├── auth/
│   └── session.py
├── scanners/
│   ├── headers.py
│   ├── xss_probe.py
│   ├── sqli_probe.py
│   └── idor_probe.py
├── reports/
│   └── report_generator.py
├── utils/
│   ├── scope.py
│   └── http_client.py
├── evidence/
└── tests/
    └── test_scope.py
~~~

## Quickstart — Windows

PowerShell window 1:

~~~powershell
cd "D:\ApplyAI\webpentest-framework\webpentest-framework"
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m playwright install chromium
python demo_target/app.py
~~~

Leave the demo target running.

PowerShell window 2:

~~~powershell
cd "D:\ApplyAI\webpentest-framework\webpentest-framework"
.\.venv\Scripts\Activate.ps1
python main.py --target http://127.0.0.1:5000
~~~

Open the generated report:

~~~powershell
Start-Process .\reports\report.html
~~~

Inspect machine-readable findings:

~~~powershell
Get-Content .\reports\findings.json
~~~

## Linux/macOS

~~~bash
python3 -m pip install -r requirements.txt
python3 -m playwright install chromium
python3 demo_target/app.py
~~~

In another terminal:

~~~bash
python3 main.py --target http://127.0.0.1:5000
~~~

## Improved failure handling

If the target is not running, the framework now exits cleanly instead of printing a long requests/urllib3 traceback:

~~~text
[ERROR] Target is unreachable.
  Target: http://127.0.0.1:5000
  Check that the authorized target is running and the host/port is correct.
  Local lab: python demo_target/app.py
~~~

The scope check still runs before any network request.

## Evidence collection

HTTP evidence is written to:

~~~text
evidence/raw_requests.jsonl
~~~

Each entry includes:

- timestamp
- scanner tag
- method
- URL
- status code
- response headers
- bounded response-body snippet
- elapsed time
- non-sensitive request headers

Authorization and Cookie request headers are excluded from the evidence log to reduce accidental credential/session exposure.

Playwright recon also writes:

~~~text
evidence/playwright_recon.json
evidence/after_login.png
evidence/products_page.png
~~~

Do not commit generated evidence or reports containing sensitive engagement data.

## Structured findings

Every finding now has a predictable reporting schema. Detectors can provide:

~~~text
id
title
severity
confidence
category
CWE
OWASP mapping
method
parameter
URL
evidence
detail
impact
remediation
references
~~~

The report generator fills safe defaults when a detector does not provide every field.

### SQLi confidence

The SQLi detector deliberately distinguishes detection signals from confirmation:

~~~text
quote causes server/error signal
        +
true/false response difference
        |
        v
possible SQL injection
        |
        v
manual validation in the authorized environment
~~~

A response-length difference alone is not sufficient proof of SQL injection.

## Reports

Each completed run produces:

~~~text
reports/findings.json
reports/report.html
~~~

The HTML report now contains:

- severity summary
- finding ID
- URL
- confidence
- category
- CWE / OWASP mapping
- parameter
- evidence
- impact
- remediation
- references
- responsive layout
- HTML escaping for finding content

## Tests

Run the scope tests:

~~~powershell
python tests/test_scope.py
~~~

If pytest is installed:

~~~powershell
python -m pytest tests/ -v
~~~

The tests verify that:

- configured local targets are allowed
- arbitrary external hosts are rejected
- assert_in_scope() raises for out-of-scope URLs
- configured hosts pass the enforcement check

## Local lab vulnerabilities

The shipped lab intentionally contains examples for learning:

- reflected XSS
- error-based SQL injection signal
- IDOR/BOLA
- missing security headers
- a secure authorization control endpoint for comparison

The lab is intentionally vulnerable and must not be exposed publicly.

## Example successful run

A successful local run should progress through:

~~~text
STEP 0 — Scope check
[OK]

STEP 1 — Reconnaissance
Discovered pages and forms

STEP 2 — Authenticated recon
Observed network requests

STEP 3 — Security header scan
Headers present / missing

STEP 4 — Reflected XSS probe
Marker reflected unescaped: True

STEP 5 — SQL injection probe
Error-based signal: True
Boolean-based signal: False

STEP 6 — IDOR probe
Other user's object: 200
Vulnerable: True

STEP 6b — Secure control
Other user's object: 403
Vulnerable: False

STEP 7 — Report generation
Findings JSON: reports\findings.json
Findings HTML: reports\report.html
~~~

The exact finding count and severity summary can change as scanners and the target change.

## Pull the latest version

After changes are committed to GitHub:

~~~powershell
cd "D:\ApplyAI\webpentest-framework\webpentest-framework"
git pull origin main
~~~

Then:

~~~powershell
.\.venv\Scripts\Activate.ps1
python main.py --target http://127.0.0.1:5000
~~~

## Extending the framework

### Add a scanner

1. Create a module under scanners/.
2. Keep probes non-destructive.
3. Use the central HTTP client for HTTP requests.
4. Check scope before any direct browser navigation or session request.
5. Return a findings list.
6. Include confidence and reproducible evidence.
7. Add tests for both positive and negative/control cases.
8. Update the report schema only when the new data is genuinely useful.

### Recommended future phases

- authenticated request evidence for IDOR/session probes
- scanner plugin registry
- deterministic finding IDs
- per-request correlation IDs
- SARIF export
- JUnit/CI output
- more negative/control tests
- configurable scan profiles
- better crawl deduplication and form discovery
- authorization-aware API inventory
- report attachments and evidence indexing

## Safety principles

This project is designed around:

1. explicit authorization
2. fail-closed scope enforcement
3. rate limiting
4. bounded timeouts
5. non-destructive detection
6. evidence minimization
7. control tests
8. reproducible findings
9. human validation before treating a detection signal as a confirmed vulnerability

## Authorized AM Webtech compatibility mode

The repository now supports a dedicated compatibility profile for the explicitly allowlisted AM Webtech domain.

Run:

    python main.py --target https://amwebtech.com --profile compatibility

Or simply:

    python main.py --target https://amwebtech.com

`auto` selects the compatibility profile for `amwebtech.com` and `www.amwebtech.com`.

### What compatibility mode checks

- scope-limited crawling
- page discovery and form inventory
- Chromium compatibility
- Firefox compatibility
- WebKit/Safari-compatible browser behavior
- mobile, tablet, laptop, desktop and large-desktop viewports
- browser console errors
- failed browser network requests
- horizontal overflow
- missing image alternative text
- potentially unlabeled form controls
- page title presence
- navigation timing observations
- full-page screenshots
- passive security-header checks
- JSON evidence
- responsive HTML reporting

Default viewports: `375x812`, `390x844`, `768x1024`, `1366x768`, `1440x900`, `1920x1080`.

Browser matrix: `Chromium`, `Firefox`, `WebKit`.

### Evidence

Compatibility evidence is stored under `evidence/`, including `evidence/compatibility.json` and browser/viewport screenshots.

Do not commit generated evidence from a real engagement if it contains confidential information.

### Live-site assessment boundary

Compatibility mode is deliberately different from the local vulnerable-lab profile. It does not automatically execute the local demo's hard-coded SQLi, XSS, or IDOR probes against a live site. Those scanners depend on application-specific routes and test accounts and must be mapped to the authorized application's actual endpoints before use.

This prevents a generic scanner from making incorrect assumptions about a production application while still providing broad browser, responsive, functional, and passive security coverage.

### Installing all Playwright browser engines

    python -m playwright install chromium firefox webkit

Then run:

    python main.py --target https://amwebtech.com --profile compatibility

If a browser engine is unavailable, the report records it rather than silently claiming that browser coverage was completed.

### Recommended assessment workflow

1. Run compatibility profile.
2. Review screenshots and `compatibility.json`.
3. Fix or validate UI and browser issues.
4. Re-run compatibility profile.
5. Map real application forms/API/auth flows.
6. Add authorized, application-specific security tests.
7. Perform manual validation.
8. Generate the final assessment report.