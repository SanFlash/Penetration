# OWASP ZAP integration

Sentinel can call a locally running OWASP ZAP API as an optional additional scanner. It produces a separate JSON report to review alongside the framework's standard report.

## Prerequisites

1. Install OWASP ZAP and start it locally with its API enabled.
2. Keep the ZAP API bound to loopback (127.0.0.1 or localhost); do not expose it to the internet.
3. Configure a ZAP API key and set ZAP_API_KEY in the environment.
4. Create a ZAP context for the approved target, review its include/exclude rules, and set ZAP_CONTEXT_NAME to that exact context name.
5. Use a dedicated staging/test instance whenever possible.

## Passive-first usage

~~~powershell
$env:ZAP_API_KEY = "your-local-zap-api-key"
$env:ZAP_CONTEXT_NAME = "Authorized staging"
python integrations/zap_runner.py --target https://staging.example.com --confirm-authorized
~~~

The adapter requires an explicit context, starts the spider inside that context, and requests subtree-only spidering. It then waits for the passive scanner queue. The queue status is global to the ZAP instance, so avoid sharing one ZAP instance with unrelated assessments.

## Active scanning

Active scanning sends attack payloads and can affect application behavior. Only use it when the target owner explicitly approves active testing and the ZAP context/scope has been checked.

~~~powershell
python integrations/zap_runner.py --target https://staging.example.com --confirm-authorized --active --confirm-active-zap --max-seconds 600
~~~

The second confirmation is mandatory. The wrapper caps its runtime budget at 30 minutes, requests alerts for the exact target origin, and filters out alert rows whose URLs do not match that origin. ZAP's context and scope remain a required defense-in-depth control; output filtering is not a substitute for configuring ZAP.

## Output

Default output: reports/zap_report.json.

The JSON contains phase status, summary counts, risk counts, alert descriptions and solutions. The API key is not written to the report. Raw HTTP request/response bodies are not included. Review each alert manually; automated results can be false positives or context-dependent.

## Coverage boundaries

This is an optional ZAP adapter, not a claim that every ZAP feature is enabled or that the framework has complete OWASP coverage. It does not automatically merge ZAP alerts into the primary HTML report, configure ZAP contexts, or prove authorization/business-logic defects. Those require explicit integration and application-specific test accounts. Do not use active scanning against production without written authorization and a tested recovery plan.

## Regression tests

~~~powershell
python -m pytest tests/test_zap_runner.py -v
python -m py_compile integrations/zap_runner.py
~~~
