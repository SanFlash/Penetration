# Sentinel Loop Engineering: OWASP and Accessibility Coverage

**Creator / Author:** Satyendra Kumar Namdeo

This document describes the repeatable engineering loop used to improve Sentinel without treating a large finding count as proof of test quality or application insecurity.

## The engineering loop

1. **Establish a baseline.** Record the commit, target origin, profile, configuration limits, discovered routes, phase statuses, current test results, and report artifacts.
2. **Map requirements.** Select relevant test scenarios from the OWASP Web Security Testing Guide (WSTG), OWASP API Security Top 10, and WCAG 2.2. Mark non-applicable or manual-only scenarios explicitly.
3. **Implement one bounded improvement at a time.** Keep requests same-origin, use inert canaries and read-only methods for production-safe tests, cap concurrency/probes/runtime, and preserve evidence provenance.
4. **Add a regression test.** Exercise a deterministic unit test or local demo target; test positive, negative, timeout/error, scope escape, and missing-evidence behavior where relevant.
5. **Run the full automated suite.** Compile modules, run all tests, inspect failures, and fix the root cause rather than weakening assertions to make CI green.
6. **Repeat until the gate passes.** Each new loop must leave previous passing behavior intact. Track remaining gaps as not run, partial, failed, or manual review—not as passing.
7. **Deploy and verify.** Wait for the deployment to become live, inspect startup/runtime logs, check health/status endpoints, and perform a small authorized smoke assessment before any full scan.
8. **Close the loop with evidence.** Generate the HTML, portable HTML, PDF/XLSX when supported, JSON, SARIF, evidence manifest and complete ZIP. Validate links and checksums; attach only real screenshots that correspond to the finding.

## OWASP security test map

The existing engines are intended to cover these areas, subject to actual phase execution and discovery:

- **WSTG information gathering and configuration:** same-origin route discovery, robots/sitemap, public documentation and exposed-resource candidates, response headers, cookie attributes, server fingerprints and error/secret patterns.
- **Identity, authentication, authorization and sessions:** passive observations and bounded authenticated discovery where test sessions are configured. Strong role and object-level authorization conclusions require at least two authorized test identities and a known permission matrix.
- **Input validation and error handling:** harmless query/header canaries, response-difference checks, reflected-input observations and error-signature checks. Reflection alone is not proof of exploitable injection.
- **Cryptography and transport:** HTTPS and relevant header/cookie observations. A browser scan is not a TLS configuration audit or proof of cryptographic correctness.
- **Business logic and workflow state:** route/method/parameter differentials and precondition checks. Domain rules, transaction integrity and replay scenarios require owner-supplied workflows and test data.
- **API security:** The report maps all ten OWASP API Security Top 10:2023 categories: object-level and property-level authorization, authentication, resource consumption, function-level authorization, sensitive business flows, SSRF, misconfiguration, inventory management, and unsafe consumption of upstream APIs. Automated phase links are evidence of engine execution only; property/role/business-flow/upstream checks require schemas, test identities, expected permissions, or controlled fixtures.
- **Information disclosure:** backup/config candidates, verbose errors, source maps and public secret-like patterns. Any secret-like match must be redacted and validated; a pattern match is not proof a credential is live.
- **Client-side security:** browser console/network observations, mixed-content candidates and response/DOM-based signals.
- **Evidence and reporting:** stable finding identifiers, execution ledger, finding-level evidence status, report bundle integrity and explicit manual-review gaps.

Reference methodology: [OWASP Top 10:2025](https://top10.owasp.org/2025/), [OWASP WSTG stable v4.2](https://wstg.owasp.org/v4.2/4-Web_Application_Security_Testing/), [OWASP WSTG latest development guide](https://wstg.owasp.org/latest/), and [OWASP API Security Top 10:2023](https://api-security.owasp.org/editions/2023/en/0x11-t10/). Reports retain the legacy Top 10:2021 matrix for compatibility and add a current Top 10:2025 matrix. Sentinel's mapping is a practical subset, not an assertion of complete OWASP coverage or certification.

## Accessibility checks

The Chromium snapshot adds automated heuristics for:

- document language and title;
- image alternative text;
- detected accessible names for form controls, links and buttons;
- main-content landmarks and heading-level jumps;
- duplicate IDs and common custom controls that are not keyboard reachable;
- potential text contrast below WCAG thresholds, using computed colors and conservative sampling.

The contrast check is intentionally marked medium confidence because backgrounds can include images, gradients, transparency, overlays, and inherited styles. The snapshot does not test every rendered state.

**Automated accessibility checks are not a WCAG conformance audit.** Manual checks are still required for keyboard-only task completion, visible focus, focus order, zoom/reflow, screen-reader announcements, error identification, accessible authentication, captions, and full interaction semantics. Use a dedicated tool such as axe-core in a controlled browser run and assistive-technology testing for deeper validation.

## Safe production boundaries

The standard full profile is aggressive in coverage but non-destructive. It must not perform denial-of-service testing, credential stuffing/brute force, exploit payloads intended to execute commands, access cloud metadata/internal networks, or create/update/delete production records. State-changing workflows belong in a disposable environment with explicit plan approval, exact scope, and verified rollback.

A “brutal” assessment means thorough route and control coverage, carefully bounded differential probes, accurate evidence, and candid reporting—not unbounded traffic or destructive tests.

## Definition of done for each loop

- [ ] Scope and target origin are enforced.
- [ ] Each enabled phase records status, duration, and errors.
- [ ] Test cases cover expected finding and clean/no-finding behavior.
- [ ] Failed checks retain useful diagnostic evidence without inventing screenshots.
- [ ] Report and ZIP include JSON, manifest, findings, and available evidence.
- [ ] Missing phases and manual-only checks remain visible in coverage.
- [ ] GitHub Actions succeeds on the exact commit being merged.
- [ ] Render deploy is confirmed live and a smoke check succeeds.
