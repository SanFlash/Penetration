# Sentinel Core Engine (v3)

**Author:** Satyendra Kumar Namdeo

The Core Engine is the shared, fail-closed execution foundation for new and migrated scanner modules.

## What it guarantees

- A request is pinned to one exact origin; scheme changes, alternate ports, user-info URLs, suffix lookalikes and non-HTTP schemes are rejected.
- The default method policy permits only GET, HEAD and OPTIONS.
- Redirects are never followed automatically.
- Each assessment has bounded request, runtime, URL, response-size, timeout and rate budgets.
- Evidence includes stable identifiers, timestamps, status, response hash and a bounded body snippet. Common secret-like values are redacted.
- Findings are deterministic and deduplicated by rule, URL, parameter and title.
- Check status is explicit: completed, partial, skipped or error. Errors never become passes.
- Reports state limitations and do not claim that automated checks establish absence of vulnerabilities.

## Integration

The primitives are in `scanners/engine_core.py`. Existing legacy scanners are migrated incrementally so each migration can be covered by regression tests without silently changing every scanner's behavior in one unsafe commit.

## Example

```python
from scanners.engine_core import AssessmentEngine, AssessmentPolicy

policy = AssessmentPolicy(
    target="https://your-authorized-host.example",
    max_probes=120,
    max_runtime_seconds=180,
    rate_per_second=2,
)
engine = AssessmentEngine(policy)
engine.register("my-check", lambda client: {
    "status": "completed",
    "checks": 1,
    "findings": [],
})
report = engine.run()
engine.write_json(report, "reports/core-report.json")
```

This is a scanner execution foundation, not a vulnerability certification. Use an owned or explicitly authorized target only. Intrusive state-change testing requires a separate disposable environment, explicit per-action authorization and verified rollback.
