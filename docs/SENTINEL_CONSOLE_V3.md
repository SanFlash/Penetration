# Sentinel Console v3

The hosted console has a task-first responsive layout with quick navigation to Assessment, Coverage Matrix, Evidence, and Execution Log. The target preview is client-side only: it checks URL shape for operator feedback and never starts a request or claims authorization. Server-side preflight and the scanner scope guards remain authoritative.

The assessment view continues to distinguish the comprehensive built-in Full Pentest pipeline from focused dropdown profiles. Coverage status comes from the report/phase ledger, not merely from selecting a profile. Missing integrations, failed phases, and manual-review categories must not be represented as passed.

## Validation

Run:

```powershell
python -m pytest tests/test_hosted_console_layout.py tests/test_hosted_console_javascript.py tests/test_hosted_console_v2.py -q
python -m pytest -q
```

The JavaScript syntax test uses Node.js when available; CI should install Node so that test is not skipped.
