# Full Coverage Profile Contract

## Full Pentest
The `pentest` dropdown profile is the comprehensive built-in pipeline. It runs reconnaissance and route discovery, browser UI/responsive/accessibility checks, read-only functional/navigation checks, information disclosure, security headers, bounded active/deep security probes, API-surface discovery, input validation/stress, attack-surface correlation, and evidence capture.

When all required external ZAP settings are present, the Full Pentest pipeline also runs the ZAP spider + passive baseline, imports origin-filtered ZAP alerts into the same final finding collection, and includes ZAP phase statuses in the phase ledger. ZAP active scanning is disabled. If the integration is not configured, its status is explicitly `not_run`; no external ZAP coverage is claimed.

## Focused dropdown profiles
`Security & OWASP`, `UI/UX`, `Functional`, `Input Validation`, `API & Attack Surface`, `Information Disclosure`, `Web Crawler & Recon`, `OWASP ZAP Baseline`, and `Core Security` intentionally run their mapped subset. They are useful for focused/repeated checks and are not aliases for Full Pentest.

## Coverage integrity
Coverage is based on the real phase ledger. A category is not reported as complete just because a profile was selected. Missing integrations, timeouts, failed phases, and manual-only areas remain visible. This black-box framework does not claim complete WSTG/WCAG/API certification: authenticated role checks, business-logic tests, source/SBOM analysis, and server-side logging verification need additional inputs or manual review.

## Regression tests
Run `python -m pytest tests/test_full_coverage_contract.py tests/test_full_pentest_zap_merge.py tests/test_hosted_console_v2.py -q`, then the complete suite.
