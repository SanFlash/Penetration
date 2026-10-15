# Sentinel finding context, visual evidence, and coverage ledger

Every normalized finding is rendered with a stable issue ID, severity/confidence, category and applicable CWE/OWASP mapping, location URL/path, HTTP method, parameter or DOM element when available, observed evidence, impact statement, remediation, and suggested validation steps.

## Finding descriptions

Descriptions are composed from fields recorded by the scanner (location, category, method, parameter, and evidence excerpt). When separate findings share the same title and category, the report adds a location-specific title suffix and varies the sentence structure. Similar observations that are intentionally consolidated retain occurrence counts and affected URL lists. This reduces repetitive prose without inventing different technical root causes.

## Screenshot and evidence behavior

- Browser evidence is captured with Chromium using same-target URL checks and read-only navigation.
- Focused error elements receive a red outline and a finding label.
- When no element can be reliably isolated, the report uses a context-only viewport image and says that it is not proof of the finding.
- If the browser time budget expires, or a finding has no URL, Sentinel creates a marked diagnostic evidence card containing the recorded context. It is explicitly labelled as a generated diagnostic artifact, not a webpage screenshot.
- Each issue links to report-local evidence files. The JSON report and evidence manifest identify attachment status and capture mode. The ZIP bundle includes report files and evidence artifacts.
- The evidence phase remains time-bounded. A diagnostic card is not a substitute for a reproducible browser capture, and unavailable artifacts remain visible as such.

## Coverage and execution ledger

The report includes phase status, recorded checks, phase duration when available, error/limitation notes, category counts, severity counts, unique findings, raw observations, affected URLs, and screenshot attachment totals. Coverage rows distinguish completed, partial, failed/timed-out, and not-run phases. Related-finding counts are category/title matches; areas can overlap, so those counts must not be summed as unique findings.

A completed engine phase is not a security certification. Authentication, role-aware authorization, business logic, server-side logs, source/dependency review, and manual accessibility checks remain limited unless the report records those tests as executed.
