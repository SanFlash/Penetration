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

Use this exact sequence on Windows. Validate the framework before contacting the live target.

### 0. Clone or update

Fresh checkout:

```powershell
git clone https://github.com/SanFlash/Penetration.git
cd Penetration
```

Existing checkout:

```powershell
cd "D:\ApplyAI\webpentest-framework\webpentest-framework"
git fetch origin
git reset --hard origin/main
git status
git log -1 --oneline
```

Keep any local evidence outside Git or stash it before a reset. Do not commit real engagement screenshots, cookies, tokens, or authorization headers.

### 1. Create and activate Python 3.11

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python --version
python -m pip --version
```

Expected Python: 3.11.x.

### 2. Install dependencies

```powershell
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

### 3. Install Chromium only

The professional browser/UI/responsive engine uses Chromium only. Firefox and WebKit are not launched by the professional profile.

```powershell
python -m playwright install chromium
```

### 4. Verify before the target

```powershell
python main.py --help
python -m py_compile main.py scanners\compatibility.py scanners\active_security.py reports\report_generator.py utils\scope.py
```

### 5. Run all framework tests

```powershell
python -m pytest tests\ -v
```

Do not start the live assessment until the test suite passes.

### 6. Run Chrome-only UI testing first

Headless:

```powershell
python main.py --target https://amwebtech.com --profile compatibility
```

Visible Chrome for debugging:

```powershell
python main.py --target https://amwebtech.com --profile compatibility --headed --slow-mo 300
```

The UI phase tests six viewports and writes JSON plus screenshots. A detected UI/browser issue gets a marked screenshot.

### 7. Review failure evidence

```powershell
Get-Content .\evidence\compatibility.json
Get-ChildItem .\evidence\chromium_*.png | Select-Object Name,Length,LastWriteTime
explorer .\evidence
```

Failure screenshots use `chromium_failure_<viewport>_<page>.png`. Normal marked UI evidence uses `chromium_<viewport>_<page>.png`.

### 8. Run the complete authorized assessment

Headless:

```powershell
python main.py --target https://amwebtech.com --profile pentest
```

Visible Chrome:

```powershell
python main.py --target https://amwebtech.com --profile pentest --headed
```

Training/debug run:

```powershell
python main.py --target https://amwebtech.com --profile pentest --headed --slow-mo 250
```

The pentest profile is fail-closed to the exact configured AM Webtech origin.

### 9. Review the final report

```powershell
Get-Content .\evidence\compatibility.json
Get-Content .\evidence\active_security.json
Start-Process .\reports\report.html
```

The report includes the findings explorer, severity/category summaries, Chrome viewport coverage, execution metadata, and links to marked screenshots.

### 10. Update the framework safely

```powershell
git status
git stash push -m "local pentest evidence before framework update" -- evidence reports
git fetch origin
git reset --hard origin/main
python -m pytest tests\ -v
```

After an update, repeat steps 4 through 9.

## Troubleshooting

### pytest is missing

```powershell
python -m pip install -r requirements.txt
python -m pytest tests\ -v
```

### Chromium cannot launch

```powershell
python -m playwright install chromium
```

### Old code is still running

```powershell
git fetch origin
git reset --hard origin/main
git log -1 --oneline
```

### A Chrome failure has no screenshot

The compatibility engine attempts a marked failure screenshot inside the exception handler. If Playwright cannot render any page surface at all, the finding records the screenshot failure reason in `compatibility.json`.

### Scope error

Use exactly `https://amwebtech.com` for the professional pentest profile. Do not disable scope enforcement.



## Controlled intrusive testing (state-changing, rollback-first)

The framework now has an explicit **intrusive** profile for a small amount of state-changing testing. This is intentionally more destructive than the normal pentest profile, but it is **not** an unrestricted destructive scanner.

Intrusive mode has two confirmations:

- `--confirm-authorized`
- `--confirm-intrusive`

It will only execute operations declared in `intrusive_plan.json`. The plan must name the exact target origin, use same-origin URLs, and provide a rollback operation for every action. Redirects are disabled.

### Supported controlled actions

- Create a disposable test resource with `POST`, then remove that resource with a configured `DELETE` rollback.
- Modify a disposable test resource with `PUT`/`PATCH` only when the original representation is supplied as `restore_json`.
- Use explicit test-resource identifiers rather than deleting arbitrary discovered data.
- Produce an audit record in `evidence/intrusive_security.json`.
- Stop and return a non-zero result if a rollback fails.

The framework does **not** discover arbitrary write endpoints and submit them, brute-force credentials, perform denial-of-service testing, execute server commands, install persistence, or delete arbitrary production data.

### Configure a disposable test resource

Copy the example plan:

~~~powershell
Copy-Item .\intrusive_plan.example.json .\intrusive_plan.json
~~~

Edit only the placeholder endpoint/resource paths so they point to a dedicated test resource that you can safely recreate or delete. Keep credentials/tokens out of Git; use environment-backed headers or another local secret mechanism when authentication is required.

Preview the operations first:

~~~powershell
python main.py --target https://amwebtech.com --profile intrusive --confirm-authorized --confirm-intrusive --intrusive-plan intrusive_plan.json --dry-run
~~~

Execute the configured actions:

~~~powershell
python main.py --target https://amwebtech.com --profile intrusive --confirm-authorized --confirm-intrusive --intrusive-plan intrusive_plan.json
~~~

Review:

~~~powershell
Get-Content .\evidence\intrusive_security.json
~~~

**Important:** do not replace the placeholder with a normal customer/user/order resource. Use a disposable test record and a verified rollback path. A failed rollback is treated as an operational stop condition.

## Dedicated security-only deep testing

The framework now has a separate security engine that does **not** launch the UI/compatibility workflow. Use it when the objective is security assessment rather than responsive/browser testing.

### Arbitrary authorized targets

The security-only engine is now target-agnostic. You can supply another web application without editing `config.py`. Each run locks itself to the exact origin you supplied, and redirects to another origin are refused.

Example:

~~~powershell
python security.py --target https://staging.example.com --confirm-authorized
~~~

With a custom port:

~~~powershell
python security.py --target https://staging.example.com:8443 --confirm-authorized
~~~

Using the integrated CLI:

~~~powershell
python main.py --target https://staging.example.com --profile security --confirm-authorized
~~~

The `--confirm-authorized` flag is intentionally required for the arbitrary-target security profile. Use it only when you own the application or have explicit authorization to assess it.

### Primary command

~~~powershell
cd "D:\ApplyAI\webpentest-framework\webpentest-framework"
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python security.py --target https://amwebtech.com --confirm-authorized
~~~

Equivalent integrated profile:

~~~powershell
python main.py --target https://amwebtech.com --profile security --confirm-authorized
~~~

Higher bounded coverage:

~~~powershell
python security.py --target https://amwebtech.com --max-urls 40 --max-probes 180
~~~

### Dedicated security-testing prompt

Use this as the operating brief for the security-only run:

~~~text
SENTINEL DEEP SECURITY — AUTHORIZED SECURITY ASSESSMENT

Target: https://amwebtech.com

Run security testing only. Do not run UI/responsive compatibility checks, do not launch Playwright/Chrome, and do not open the visual dashboard.

Perform an aggressive, high-coverage, non-destructive web security assessment within the exact target origin. Discover same-origin pages, query parameters, forms, JavaScript assets, robots/sitemap metadata and documented API surfaces. Test security headers, cookie flags, CORS behavior, HTTP method exposure, TRACE reflection, input reflection, SQL/error signatures, redirect handling, CRLF/header-injection signals, host-header handling, URL override headers, error disclosure, JavaScript/source-map leakage, sensitive configuration/backup exposure and path/routing inconsistencies.

For every probe record the exact URL, HTTP method, status, response length, timing, baseline comparison, parameter/header/vector, and a concise evidence summary. Never store or print actual secrets discovered in page source.

Keep redirects disabled so the engine never follows the target into another origin. Enforce the exact https://amwebtech.com origin before every request. Stop at the configured request/probe budget and rate limit.

Do not brute-force credentials, submit discovered state-changing forms, upload files, modify/delete data, execute server commands, perform denial-of-service testing, or attempt persistence.

Generate:
- evidence/deep_security.json
- reports/findings.json
- reports/report.html

Treat automated signals as candidates that require manual validation. Do not call a reflection, error message, missing header, or response difference a confirmed exploit without sufficient evidence.
~~~

### What the security-only engine tests

The dedicated engine currently performs:

- exact-origin fail-closed scope enforcement
- same-origin reconnaissance
- bounded baseline GET collection
- security-header checks
- technology/banner disclosure checks
- cookie Secure/HttpOnly observations
- OPTIONS method enumeration
- TRACE reflection testing
- controlled query-parameter mutation
- inert reflected-input detection
- database/framework error-signature detection
- redirect-parameter testing with redirects disabled
- CRLF/header-injection canaries
- Host and X-Forwarded-Host reflection checks
- X-Original-URL / X-Rewrite-URL routing behavior checks
- HTML source leakage heuristics
- JavaScript and source-map exposure checks
- common configuration/backup/API documentation exposure checks
- invalid-route verbose-error detection
- deterministic JSON evidence and the existing interactive report

These checks are aligned to areas covered by the OWASP Web Security Testing Guide, including HTTP methods, input validation/injection, host-header handling, authorization/header-routing behavior, metadata leakage and security-header configuration.

### Important meaning of "aggressive"

"Deep/aggressive" in this framework means **more security coverage and stronger detection**, not destructive exploitation. The engine intentionally stops short of actions that can alter production state or create an outage. It is suitable for an authorized owned site such as the configured AM Webtech target, but findings still need manual confirmation.

### Security-only output

After the run:

~~~powershell
Get-Content .\evidence\deep_security.json
Start-Process .\reports\report.html
~~~

The report is security-focused; it does not require Chrome evidence to populate its security findings.


## Enhanced evidence-first workflow

The current framework revision extends the original scanner into an evidence-first assessment pipeline. The HTML report now consumes pentest coverage from `ui_responsive` as well as the older `compatibility` metadata shape, so the Coverage tab is populated during a pentest run.

### Complete run order

1. Sync the repository.
2. Activate Python 3.11.
3. Install dependencies.
4. Install Chromium only.
5. Run syntax validation.
6. Run the complete pytest suite.
7. Run Chrome-only compatibility testing first.
8. Inspect `evidence/compatibility.json` and screenshots.
9. Run the full pentest profile.
10. Run bounded URL mutation checks.
11. Capture Chrome security evidence for selected findings.
12. Open `reports/report.html`.
13. Review the Evidence gallery and Coverage matrix.
14. Manually validate important findings.

### Exact Windows command sequence

```powershell
cd "D:\ApplyAI\webpentest-framework\webpentest-framework"
git fetch origin
git reset --hard origin/main
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m playwright install chromium
python -m py_compile main.py scanners\compatibility.py scanners\active_security.py scanners\browser_evidence.py reports\report_generator.py utils\scope.py
python -m pytest tests\ -v
```

### Chrome UI phase

```powershell
python main.py --target https://amwebtech.com --profile compatibility --headed --slow-mo 300
```

Review:

```powershell
Get-Content .\evidence\compatibility.json
Get-ChildItem .\evidence\chromium_*.png | Select-Object Name,Length,LastWriteTime
```

### Full advanced profile

```powershell
python main.py --target https://amwebtech.com --profile pentest --headed --slow-mo 250
```

The full profile now runs:

- exact-origin scope enforcement
- same-host reconnaissance
- Chrome-only six-viewport testing
- passive security-header checks
- CORS checks
- HTTP method exposure checks
- inert reflected-input testing
- bounded GET-only URL mutation
- server/database error-signature detection
- CSRF posture inspection without form submission
- verbose error disclosure testing
- mixed-content detection
- Chrome security evidence capture
- interactive JSON/HTML reporting

### URL mutation mode

The advanced URL layer is intentionally a controlled mutation engine rather than a destructive exploit engine. It mutates discovered query parameters using bounded harmless/syntax-oriented vectors and compares responses against the baseline.

Recorded observations include:

- baseline HTTP status
- mutated HTTP status
- response-length change
- reflection of a unique marker
- database/framework error signatures
- exact mutated URL
- parameter name
- mutation vector
- evidence URL

OWASP describes fuzzing as repeated request generation followed by analysis of response status, timing and other characteristics, and notes that injection testing can have destructive consequences when state-changing database operations are reached. This implementation therefore remains GET-only and bounded.

### Security screenshots

Selected active findings are replayed in Chromium and receive visual evidence.

Generated files:

```text
evidence/security_*.png
evidence/security_failure_*.png
evidence/security_browser_evidence.json
reports/evidence_manifest.json
```

Each relevant finding in `reports/findings.json` contains a screenshot reference when capture succeeded.

### Report tabs

- **Overview** — severity, category and evidence-health metrics.
- **Findings** — searchable technical findings with evidence, impact, remediation and screenshots.
- **Coverage** — actual Chrome/viewport results, status, timing, console/network errors and screenshots.
- **Evidence** — screenshot gallery plus security-capture log. Failure screenshots are explicitly marked.
- **Execution** — raw run metadata for reproducibility.

OWASP reporting guidance recommends that findings contain enough information to reproduce and remediate an issue and specifically calls for screenshots/test artifacts where useful.

### Evidence troubleshooting

If the Evidence tab is empty, generate a fresh run. The report references files created by that run.

```powershell
Get-ChildItem .\evidence\*.png
Get-Content .\evidence\security_browser_evidence.json
Get-Content .\reports\evidence_manifest.json
Start-Process .\reports\report.html
```

If a finding has no screenshot, it may be a passive/header observation or Chromium may have been unable to render the evidence URL. The report records that state instead of pretending evidence exists.

### Important interpretation rule

A browser screenshot proves what the automated browser observed at that point in time. It does not by itself prove exploitability. Reflection, HTTP 5xx responses, missing headers, and other automated signals should be manually validated before being treated as confirmed vulnerabilities.

OWASP similarly recommends balancing automated breadth with manual/semi-automated validation and warns that the testing guide is not an exhaustive checklist.

### Destructive testing is intentionally excluded

The framework does not automatically perform credential brute force, data deletion, malware upload, denial-of-service testing, or destructive PUT/DELETE/PATCH operations. If a later lab-only module is added for destructive validation, it should be explicitly opt-in and separately scoped.

OWASP's HTTP-method guidance specifically cautions that destructive method testing can change server state and should be handled with extreme care.


## Industry-mode authorized pentesting

The `pentest` profile is the full assessment path for an explicitly authorized web application. It accepts an arbitrary absolute HTTP(S) origin when `--confirm-authorized` is supplied; every HTTP and browser request remains locked to that exact scheme + host + port origin and redirects are not followed across origins.

### Full deep assessment

~~~powershell
python main.py --target https://your-authorized-site.example --profile pentest --confirm-authorized
~~~

For a visible Chromium run:

~~~powershell
python main.py --target https://your-authorized-site.example --profile pentest --confirm-authorized --headed --slow-mo 250
~~~

Security-only mode remains available when browser/UI checks are not wanted:

~~~powershell
python security.py --target https://your-authorized-site.example --max-urls 60 --max-probes 500 --api-surface --confirm-authorized
~~~

The full pentest now combines:
- same-origin reconnaissance and form/parameter discovery
- Chromium responsive/browser evidence
- passive response-header and cookie posture checks
- bounded active CORS, HTTP-method, reflection, CSRF-posture and mixed-content checks
- deep GET/OPTIONS/TRACE security testing with query mutations, routing-header checks, error disclosure, source-map/client-artifact review and sensitive-path exposure checks
- passive OpenAPI/Swagger attack-surface inventory
- screenshot evidence for selected findings
- issue-level report aggregation so repeated URL observations are retained as evidence without inflating the unique finding count

### Raw observations vs unique findings

Sentinel preserves every scanner observation for forensic traceability, while the interactive report aggregates repeated security observations into issue-level findings. For example, the same missing-header condition observed on 40 pages is shown as one issue with its affected URLs and observation count, while the raw scanner count remains available.

The report exposes:
- `raw_findings`: scanner observations before report aggregation
- `unique_findings`: issue-level report rows
- `total_observations`: retained observation count represented by those rows
- `affected_urls` and `observation_ids` on aggregated findings

This prevents a broad scan from turning one control weakness into dozens of misleading vulnerability rows while preserving evidence for remediation and retesting.

### Assessment boundary

"Brutal" or "aggressive" means deeper coverage and more test cases, not destructive behavior. The automated engine deliberately does not brute-force credentials, submit arbitrary state-changing forms, upload/delete data, execute server commands, persist on the target, or intentionally cause denial of service. Those activities are not appropriate as a default production scanner.

Automated results remain candidates for validation. OWASP's WSTG recommends automated tools for breadth and repeatability while balancing them with manual and application-specific testing; its reporting guidance recommends reproducible finding details and evidence.

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
├── security.py
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
## Security Phase 4 — API attack-surface inventory

Phase 4 adds a passive OpenAPI/Swagger inventory layer. OWASP's API Security Top 10 emphasizes API inventory and authorization risks; this module focuses on discovering and documenting the API surface before deeper authenticated testing.

### Run the API inventory

`powershell
python security.py --target https://amwebtech.com --api-surface --confirm-authorized
`

For another authorized application:

`powershell
python security.py --target https://staging.example.com --api-surface --confirm-authorized
`

The API layer:

- probes common OpenAPI/Swagger JSON locations
- discovers same-origin API documentation links from the root page
- parses OpenAPI 3 and Swagger 2 JSON documents
- inventories documented paths, HTTP methods, operation IDs and parameters
- records documented state-changing operations
- identifies deprecated operations
- identifies operations that explicitly override inherited security with an empty security requirement
- records external server origins advertised by the API specification without requesting them
- keeps exact-origin scope enforcement and redirects disabled
- does not submit forms, authenticate, brute-force credentials, modify data or perform DoS testing

Evidence is written to:

`text
evidence/api_surface.json
`

### Phase 4 workflow

`powershell
python -m py_compile scanners\\api_surface.py security.py
python -m pytest tests\\test_api_surface.py -v
python security.py --target https://amwebtech.com --api-surface --confirm-authorized
Get-Content .\\evidence\\api_surface.json
`

API inventory observations are not automatically vulnerabilities. Public API documentation and documented POST/DELETE routes may be intentional; the inventory is the input for later role-aware authorization and business-logic testing.


## Passive route and API-candidate discovery

The API inventory now includes a passive route-discovery phase for applications that do not publish OpenAPI/Swagger documentation.

The discovery engine:

- follows a bounded number of same-origin HTML pages
- extracts links and form actions
- inspects same-origin JavaScript assets
- recognizes common `fetch`, Axios and XMLHttpRequest route patterns
- identifies API-like paths such as `/api/*`, `/graphql` and `/rest/*`
- records POST/PUT/PATCH/DELETE candidates without submitting them
- keeps exact-origin locking and redirects disabled
- performs only GET requests during discovery
- writes deterministic evidence to `evidence/discovered_routes.json`

### Route discovery output

After a security or pentest run:

```powershell
Get-Content .\evidence\discovered_routes.json
```

The evidence contains:

- pages inspected
- JavaScript assets inspected
- discovered routes
- HTTP method
- whether the method is state-changing
- API-like classification
- discovery source
- source page/asset
- bounded evidence snippet

A state-changing candidate is an **inventory item**, not permission to execute it. It must be manually reviewed before any controlled intrusive plan is created.

### Security-only profile

The security profile now reports passive route/API discovery in addition to deep GET/HEAD/OPTIONS/TRACE testing:

```powershell
python main.py --target https://amwebtech.com --profile security --confirm-authorized
```

Expected output includes:

```text
PASSIVE ROUTE / API DISCOVERY
[MODE] GET-only discovery; discovered POST/PUT/PATCH/DELETE routes are inventory candidates.
Pages inspected: ...
JavaScript assets inspected: ...
Routes discovered: ...
API-like routes: ...
State-changing candidates: ...
API specifications: ...
Documented API endpoints: ...
```

This is specifically designed for applications such as AM Webtech where common OpenAPI/Swagger locations may return 404.

### Safety boundary

Passive route discovery never submits discovered forms and never sends POST, PUT, PATCH or DELETE requests. It is therefore suitable as the discovery stage before the separately gated controlled-intrusive workflow.

The intrusive workflow still requires:

1. explicit authorization
2. `--confirm-intrusive`
3. a configured disposable resource
4. an explicit rollback operation
5. exact target-origin validation
6. no unresolved template placeholders



## Live scan progress and runtime controls

Security scans now expose visible CLI progress instead of appearing idle during long GET-only phases.

Typical output:

```text
[STAGE 1/2] Deep security assessment starting...
[DEEP] Crawl starting: max_urls=60, max_probes=500, timeout=10s
[DEEP] probes=10/500 | latest=GET 200 | https://target.example/page | runtime=5.2s
...
[STAGE 2/2] Passive route/API discovery starting...
[DISCOVERY] Starting passive route discovery (max 8 pages, 20 JS assets, 120s budget)
[DISCOVERY] GET 01 | 200 | https://target.example/
[DISCOVERY] JS asset 1/5 | https://target.example/static/app.js
[API] GET 02/100 | 404 | https://target.example/openapi.json
```

Route discovery is additionally protected by a bounded runtime budget and shorter request timeout so a slow endpoint cannot make the discovery phase appear indefinitely stuck.

Configuration:

- `SECURITY_PROGRESS_INTERVAL` — number of deep-security probes between progress messages.
- `ROUTE_DISCOVERY_TIMEOUT` — per-request route-discovery timeout.
- `ROUTE_DISCOVERY_MAX_RUNTIME` — maximum route-discovery runtime in seconds.

The scanner remains exact-origin, redirects-disabled, GET-only for passive discovery, and non-destructive by default.

