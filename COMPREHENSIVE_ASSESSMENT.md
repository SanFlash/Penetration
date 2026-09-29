# Comprehensive Authorized Assessment

This module adds a broader, read-only security pass for an explicitly authorized target.

## Run

```powershell
python comprehensive.py --target https://amwebtech.com --confirm-authorized
```

Or with explicit limits:

```powershell
python comprehensive.py --target https://amwebtech.com --confirm-authorized --max-urls 80 --max-probes 260
```

The scanner performs same-origin GET/OPTIONS checks with redirects disabled and a bounded request rate.

## Additional coverage

- security-header consistency
- HSTS, CSP, X-Content-Type-Options, Referrer-Policy, Permissions-Policy and X-Frame-Options
- Server/X-Powered-By fingerprint disclosure
- Secure, HttpOnly and SameSite cookie posture
- cache-control observations on sensitive-looking routes
- verbose diagnostic/error signatures
- credential/private-key-like pattern detection in public responses
- directory-listing detection
- common exposed-resource checks such as `/.env`, `/.git/HEAD`, diagnostic endpoints and common API documentation locations
- OPTIONS/Allow method exposure
- robots/sitemap/security.txt and common cross-domain policy discovery
- GraphQL/OpenAPI/Swagger candidate discovery without executing mutations

All findings are candidates and require validation. The scanner does not submit forms, upload files, create/update/delete records, brute-force credentials or intentionally cause denial of service.

## Controlled disposable-resource testing

For a test environment where state changes are explicitly required, use:

```powershell
python controlled_assessment.py --target https://amwebtech.com --plan intrusive_plan.json --confirm-authorized --confirm-intrusive --dry-run
```

A real run additionally requires `--confirm-destructive`.

The existing plan validator requires a disposable resource, exact-origin scope and rollback. It rejects unresolved placeholders, standalone DELETE actions and missing rollback definitions.

## Evidence

The comprehensive scanner writes:

```text
evidence/comprehensive_security.json
reports/findings.json
reports/report.html
```

The design follows the OWASP WSTG principle of mapping the application before active testing and documenting reproducible evidence. Automated results should be manually validated before remediation decisions.
