# Sentinel Web Pentest Framework

A Python + Playwright web-application assessment framework for **owned or explicitly authorized targets**. It combines scope enforcement, reconnaissance, Chrome-only responsive evidence, passive security checks, bounded active checks, evidence capture, a local visual console, and interactive reporting.

> **Authorization:** Only test systems you own or have explicit written permission to assess. The configured AM Webtech target is enabled because the project owner has stated that it is authorized for assessment.

## What the professional profile does

For `https://amwebtech.com`, the recommended profile is:

```text
Scope
  ↓
Reconnaissance
  ↓
Chrome-only responsive evidence
  ├─ 375×812
  ├─ 390×844
  ├─ 768×1024
  ├─ 1366×768
  ├─ 1440×900
  └─ 1920×1080
  ↓
Passive security headers
  ↓
Bounded active security checks
  ├─ CORS policy/reflection
  ├─ advertised HTTP methods
  ├─ inert reflected-input canaries
  ├─ CSRF posture inspection
  ├─ verbose error disclosure
  └─ HTTPS mixed-content references
  ↓
Evidence + findings
  ↓
Interactive JSON/HTML report
```

The browser phase intentionally uses **Chromium only** to reduce runtime. It does not install or launch Firefox/WebKit for the professional profile.

## Important scope of automation

This framework is an automated assessment layer, not a guarantee of complete penetration-test coverage. OWASP WSTG currently describes active testing across information gathering, configuration/deployment, identity, authentication, authorization, session management, injection, error handling, weak cryptography, business logic, client-side and API testing. OWASP also notes that automated tools provide breadth while application-specific and business-logic testing requires manual/semi-automated work.

- OWASP WSTG: https://wstg.owasp.org/latest/
- OWASP project page: https://owasp.org/projects/web-security-testing-guide
- ZAP Automation Framework: https://www.zaproxy.org/docs/automate/automation-framework/

Use this project to automate repeatable coverage and evidence, then add authorized test accounts, API specifications, role matrices, workflow definitions, and manual validation for deeper application-specific testing.

## Windows setup

```powershell
cd "D:\ApplyAI\webpentest-framework\webpentest-framework"
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m playwright install chromium
```

Only Chromium is required for the professional UI/responsive phase.

Verify:

```powershell
python main.py --help
python -m py_compile main.py scanners\compatibility.py scanners\active_security.py
```

The CLI should show:

```text
--profile {auto,lab,compatibility,pentest}
```

## Commands for AM Webtech

### 1. Recommended full authorized assessment

```powershell
python main.py --target https://amwebtech.com --profile pentest
```

This runs the complete bounded automated flow.

### 2. Full assessment with visible Chrome

```powershell
python main.py --target https://amwebtech.com --profile pentest --headed
```

### 3. Slow visible run for training/debugging

```powershell
python main.py --target https://amwebtech.com --profile pentest --headed --slow-mo 250
```

`--slow-mo` accepts 0–5000 ms.

### 4. Disable the visual dashboard

```powershell
python main.py --target https://amwebtech.com --profile pentest --no-dashboard
```

### 5. Automatic profile selection

```powershell
python main.py --target https://amwebtech.com
```

The `auto` profile selects `pentest` for AM Webtech.

### 6. UI/responsive-only assessment

```powershell
python main.py --target https://amwebtech.com --profile compatibility
```

Visible Chrome:

```powershell
python main.py --target https://amwebtech.com --profile compatibility --headed --slow-mo 300
```

## What the Chrome phase checks

Each discovered page is tested at six responsive viewport sizes:

| Viewport | Purpose |
|---|---|
| 375×812 | small mobile |
| 390×844 | large mobile |
| 768×1024 | tablet |
| 1366×768 | laptop |
| 1440×900 | desktop |
| 1920×1080 | large desktop |

Checks include:

- HTTP/navigation status
- browser console errors
- failed browser requests
- horizontal overflow
- missing image `alt` attributes
- potentially unlabeled controls
- document title
- navigation timing
- full-page screenshots

### Marked visual evidence

When a UI/browser issue is detected, Sentinel injects a non-destructive visual banner before taking the screenshot.

Examples:

```text
SENTINEL // EVIDENCE MARKER
CONSOLE ERRORS: 2
NETWORK FAILURES: 1
HORIZONTAL OVERFLOW: 1280px > 375px
MISSING ALT: 4
UNLABELED CONTROLS: 3
```

The marker is included only in the captured evidence screenshot; it is not sent as a request to the application.

Evidence is stored as:

```text
evidence/chromium_<viewport>_<page>.png
evidence/compatibility.json
```

Findings that originate from the browser checks retain the associated screenshot path.

## Active security layer

The professional profile uses bounded, non-destructive active checks.

### CORS

Sends a deliberately invalid Origin and inspects whether the response reflects it, including credentialed CORS behavior.

### HTTP method exposure

Inspects advertised methods and reports potentially unnecessary state-changing/diagnostic methods.

### Reflected input

For already-discovered query parameters, replaces one parameter value with an inert unique canary and checks whether it is reflected. Reflection alone is **not** reported as proof of XSS.

### CSRF posture

Reviews discovered state-changing forms without submitting them. A missing conventional token is an observation requiring application-specific validation.

### Error disclosure

Requests one random non-existent path and looks for common verbose-error signatures.

### Mixed content

On HTTPS pages, checks for direct HTTP resource references.

The active layer does **not**:

- brute-force credentials
- perform credential stuffing
- upload malware
- delete application data
- intentionally cause denial of service
- bypass the framework's scope control
- submit discovered state-changing forms merely to prove a finding

## Evidence and reports

Generated runtime files:

```text
evidence/
  raw_requests.jsonl
  compatibility.json
  active_security.json
  chromium_*.png

reports/
  findings.json
  report.html
```

Open the report:

```powershell
Start-Process .\reports\report.html
```

Inspect active-security evidence:

```powershell
Get-Content .\evidence\active_security.json
```

Inspect Chrome evidence:

```powershell
Get-Content .\evidence\compatibility.json
```

Do not commit real engagement screenshots, cookies, tokens, authorization headers, or sensitive request/response data.

## Local vulnerable lab

The repository includes a deliberately vulnerable Flask lab for learning.

Terminal 1:

```powershell
python demo_target\app.py
```

Terminal 2:

```powershell
python main.py --target http://127.0.0.1:5000 --profile lab
```

The lab contains controlled examples for reflected XSS, SQL injection signals, IDOR/BOLA, and security-header weaknesses.

## Project structure

```text
Penetration/
├── main.py
├── config.py
├── requirements.txt
├── demo_target/
├── recon/
├── auth/
├── scanners/
│   ├── headers.py
│   ├── xss_probe.py
│   ├── sqli_probe.py
│   ├── idor_probe.py
│   ├── compatibility.py
│   └── active_security.py
├── reports/
├── ui/
├── utils/
├── evidence/
└── tests/
```

## Testing the framework

Before a live assessment:

```powershell
python -m py_compile main.py scanners\compatibility.py scanners\active_security.py reports\report_generator.py
python -m pytest tests\ -v
```

The framework should pass syntax checks before any live target is contacted.

## Operational workflow

Recommended workflow for AM Webtech:

1. Pull the current repository.
2. Activate the virtual environment.
3. Install requirements.
4. Install Chromium.
5. Run `py_compile`.
6. Run the pentest profile.
7. Monitor the local Sentinel dashboard.
8. Review marked screenshots.
9. Review `active_security.json`.
10. Review `reports/report.html`.
11. Manually validate significant findings.
12. Retest after remediation.
13. Keep engagement evidence separate from source control.

## Future industry-oriented modules

The architecture is intended to grow toward:

- authenticated test-account workflows
- role/authorization matrices
- API/OpenAPI discovery
- session lifecycle testing
- controlled IDOR/BOLA workflows
- application-specific business-logic tests
- CSP and client-side security analysis
- source-map and exposed-artifact detection
- controlled directory/configuration exposure checks
- SARIF/JUnit output
- CI/CD integration
- optional ZAP integration
- evidence hashing and correlation IDs
- manual-test checklist generation

An optional ZAP active-scan integration should remain explicitly opt-in because ZAP documents that active scanning attacks the application and should only be used with permission.

## Git update commands

```powershell
git status
git fetch origin
git pull --rebase origin main
git log -1 --oneline
```

If generated `evidence/` or `reports/` files are modified locally, stash those artifacts before updating the framework:

```powershell
git stash push -m "local pentest evidence before framework update" -- evidence reports
git pull --rebase origin main
```

## Safety model

The framework follows these principles:

1. explicit authorization
2. fail-closed scope enforcement
3. bounded request volume
4. bounded timeouts
5. non-destructive active checks
6. minimized evidence
7. reproducible findings
8. manual validation of important signals

OWASP describes the WSTG as a methodology rather than an exhaustive checklist, and recommends balancing automated breadth with manual and application-specific depth.