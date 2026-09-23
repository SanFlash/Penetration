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

## Latest AM Webtech compatibility workflow

The framework now supports a dedicated authorized compatibility profile for amwebtech.com, including visible Playwright browser testing.

### Update your local copy

    cd "D:\ApplyAI\webpentest-framework\webpentest-framework"
    git pull origin main
    .\.venv\Scripts\Activate.ps1
    python -m pip install -r requirements.txt
    python -m playwright install chromium firefox webkit

Verify the CLI:

    python main.py --help

### Run AM Webtech compatibility testing

Headless:

    python main.py --target https://amwebtech.com --profile compatibility

Visible browser windows:

    python main.py --target https://amwebtech.com --profile compatibility --headed

Recommended visual run:

    python main.py --target https://amwebtech.com --profile compatibility --headed --slow-mo 300

Use 500-1000 ms if you want to watch the actions more slowly. The accepted range is 0-5000 ms.

### Visual browser matrix

- Chromium
- Firefox
- WebKit (Safari-compatible engine)

Viewport matrix:

- 375x812 — mobile small
- 390x844 — mobile large
- 768x1024 — tablet
- 1366x768 — laptop
- 1440x900 — desktop
- 1920x1080 — large desktop

With headed mode, Playwright opens the browser windows while each page/viewport combination is tested. The terminal also prints progress such as:

    [BROWSER] chromium | [VIEWPORT] mobile-small | https://amwebtech.com/

### Current automated checks

- scope-limited crawling
- page and form discovery
- browser console errors
- failed browser network requests
- horizontal overflow
- missing image alt attributes
- potentially unlabeled form controls
- page title presence
- navigation timing observations
- full-page screenshots
- passive security-header checks
- JSON evidence
- HTML reporting

### Evidence and reports

Evidence is written under:

    evidence/

Important files include:

    evidence/compatibility.json
    evidence/chromium_*.png
    evidence/firefox_*.png
    evidence/webkit_*.png

Reports are written under:

    reports/findings.json
    reports/report.html

Open the HTML report:

    Start-Process .\reports\report.html

Read compatibility JSON:

    Get-Content .\evidence\compatibility.json

### Local vulnerable lab

Start the local lab in one terminal:

    python demo_target/app.py

Then run in another:

    python main.py --target http://127.0.0.1:5000 --profile lab

### Safety boundary for the live site

The AM Webtech compatibility profile is deliberately different from the local vulnerable-lab profile. It does not blindly execute the lab's hard-coded SQLi, XSS, or IDOR routes against a production application. Those tests must first be mapped to real, authorized application endpoints and test accounts.

Automated findings are signals that should be manually validated before being treated as confirmed defects or vulnerabilities.

### Real-device limitation

WebKit provides Safari-engine coverage but is not a physical iPhone/iPad. Chromium mobile viewports are not equivalent to every physical Android device. A future real-device phase should cover iOS Safari, Android Chrome, touch behavior, orientation, mobile keyboards, and real network conditions.

### Recommended next workflow

1. Pull the latest repository.
2. Install all Playwright browser engines.
3. Run the headed AM Webtech assessment with slow motion.
4. Review screenshots and compatibility.json.
5. Open reports/report.html.
6. Group findings by browser, viewport, page, and severity.
7. Fix and re-run the affected workflows.
8. Add application-specific functional/API/authentication tests.
9. Perform manual validation.
10. Generate the final assessment report.

### Framework tests

    python tests/test_scope.py

If pytest is installed:

    python -m pytest tests/ -v

### Git commands

Check status:

    git status

Review recent commits:

    git log --oneline -10

Update:

    git pull origin main

Do not commit real engagement screenshots, request logs, or reports if they contain confidential information.


## Professional visual assessment console

The compatibility profile now includes a local visual monitoring console. The Playwright assessment can remain headless while the dashboard runs visibly in your normal browser.

When a compatibility assessment starts, the framework opens:

    http://127.0.0.1:8765/

The dashboard shows:

- animated assessment visualization
- current assessment stage
- target and profile
- active browser engine
- active viewport
- progress percentage
- pages and browser checks
- finding/error counters
- live console telemetry
- browser/viewport matrix
- assessment completion status

### Recommended headless + visual dashboard command

    python main.py --target https://amwebtech.com --profile compatibility

The Playwright engines remain headless, while the Sentinel dashboard opens in your normal browser.

### Headed Playwright + dashboard

If you also want the actual Playwright browser windows visible:

    python main.py --target https://amwebtech.com --profile compatibility --headed --slow-mo 300

This gives you both:

    Sentinel dashboard
          +
    visible Playwright browser windows

### Disable the dashboard

For CI/server environments:

    python main.py --target https://amwebtech.com --profile compatibility --no-dashboard

### Console loader

The terminal now displays a continuously updating loader while the assessment is running:

    [/] [chromium/mobile-small] https://amwebtech.com/
    [-] [chromium/tablet] https://amwebtech.com/
    [\] Scanning security headers
    [|] Building interactive analytics report

The dashboard receives the same telemetry.

## Interactive assessment report

reports/report.html has been upgraded from a basic findings page to an interactive assessment report.

It now contains:

### Overview

- severity distribution
- total findings
- category count
- high-confidence count
- browser-check count
- category distribution bars

### Findings explorer

- live search
- severity filter
- category filter
- expandable evidence
- impact
- remediation
- CWE
- OWASP mapping
- URL
- confidence
- finding IDs

### Coverage

The report can display the browser/viewport matrix with:

- browser engine
- viewport
- HTTP status
- load timing
- console error count
- network failure count
- horizontal overflow

### Evidence

The report includes execution metadata and the compatibility evidence directory.

Open the report after an assessment:

    Start-Process .\reports\report.html

## Updated architecture

    CLI
      |
      +--> Scope enforcement
      |
      +--> Reconnaissance
      |
      +--> Live Dashboard ----> http://127.0.0.1:8765
      |
      +--> Playwright matrix
      |       +-- Chromium
      |       +-- Firefox
      |       +-- WebKit
      |       +-- 6 responsive viewports
      |
      +--> Passive security checks
      |
      +--> Evidence collection
      |
      +--> Interactive JSON/HTML report

## Latest recommended workflow

    cd "D:\ApplyAI\webpentest-framework\webpentest-framework"
    git pull origin main
    .\.venv\Scripts\Activate.ps1
    python -m pip install -r requirements.txt
    python -m playwright install chromium firefox webkit

Then:

    python main.py --target https://amwebtech.com --profile compatibility

For the most visual development run:

    python main.py --target https://amwebtech.com --profile compatibility --headed --slow-mo 300

Then open:

    Start-Process .\reports\report.html

## Industry-oriented roadmap

The framework is being evolved toward a reusable assessment platform with:

- explicit target profiles
- scope enforcement
- browser/device compatibility
- responsive QA
- accessibility signals
- performance observations
- passive security analysis
- application-specific security modules
- evidence preservation
- interactive reporting
- CI-friendly execution
- real-device integrations
- baseline/visual regression
- API and authentication workflow testing

Automated findings remain observations until they are validated in the authorized environment.
