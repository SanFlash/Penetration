# Sentinel Core Engine v3

**Author:** Satyendra Kumar Namdeo

The Core Engine is an executable, bounded security-assessment path. It complements the existing dashboard profiles while scanner modules are migrated behind one shared transport.

## Run it

Use Python 3.11+ and install the repository requirements. Only scan systems you own or have explicit written authorization to assess.

```powershell
python -m pip install -r requirements.txt
python main.py --profile core --target https://your-authorized-host.example --confirm-authorized
```

Bound runtime and request volume explicitly for a first run:

```powershell
python main.py --profile core --target https://your-authorized-host.example --confirm-authorized --core-max-urls 15 --core-max-probes 60
```

Output is written to the configured report/evidence directories:
- `core_report.json` — structured findings, phase statuses, request summaries, evidence hashes and limitations.
- `core_report.html` — readable report with severity, evidence summary and remediation.
- `sentinel_core_bundle.zip` — report files plus captured evidence JSONL.

The CLI requires `--confirm-authorized`; this is an operator confirmation, not a technical proof of ownership. The scan pins requests to the target's exact origin. Redirects are recorded but never followed.

## What it checks

- Same-origin page discovery (GET only, bounded page count).
- Security response headers and cookie attribute heuristics.
- Path-specific signatures for common public exposure risks; generic 200/SPA fallbacks are not enough to create a finding.
- Inert query reflection and single-quote error-handling triage on observed query URLs. These are candidates, not proof of XSS or SQL injection.
- A sentinel-origin CORS check; a finding requires origin reflection plus credential allowance.
- Deterministic finding IDs, evidence references, response hashes and redacted evidence snippets.

## Execution guarantees

- Exact origin locking; malformed URLs, credentials embedded in URLs, scheme changes and host lookalikes are rejected.
- GET, HEAD and OPTIONS are the only methods allowed by the core policy.
- Redirects disabled, TLS verification enabled, bounded connect/read timeout, response body size, request count, runtime and rate.
- Check outcomes remain distinct: completed, partial, skipped or error. An exception is never recorded as a pass.
- The report explicitly describes automation limitations. Automated heuristics are not a penetration-test certification.

## Known limitations

The Core Engine is an initial migration path, not a replacement for every legacy scanner yet. It does not submit forms, authenticate to applications, attempt credential attacks, upload files, change or delete server data, execute denial-of-service tests, or establish business-logic authorization flaws automatically. Browser screenshots are produced by the existing browser-evidence path, not by this HTTP-only core CLI. Validate high-impact candidates manually in a controlled staging environment.
