## Evidence integrity checks

Sentinel includes `scanners.evidence_integrity` helpers to validate screenshot
references before packaging reports. The validator checks that each referenced
file stays within the evidence directory, exists, is non-empty, has a plausible
image signature, and receives a SHA-256 digest. It reports missing/invalid
artifacts instead of treating a screenshot path as proof that evidence exists.

Example:

```python
from scanners.evidence_integrity import write_evidence_manifest

write_evidence_manifest(
    findings=findings,
    evidence_root="reports/evidence",
    output_path="reports/evidence_integrity.json",
)
```

The generated manifest is an integrity ledger, not a vulnerability verdict.
A valid image can still be irrelevant to a finding. Review screenshots for
relevance and redact credentials, session identifiers, personal data, and
other secrets before sharing. The validator makes no network requests and
does not increase target traffic.

## Live-target testing boundaries

Use the `pentest` profile only for a target you are authorized to assess.
Prefer read-only probes and bounded request rates on production systems. Do not
run denial-of-service, destructive state changes, credential attacks, or tests
that access real users' data. Mark authenticated and business-logic tests as
manual/incomplete when test accounts and expected outcomes are not supplied.
