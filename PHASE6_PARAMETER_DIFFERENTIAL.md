# Phase 6 — Authenticated Parameter Differential Testing

Phase 6 tests one explicitly selected authorization-sensitive parameter using
two authorized disposable accounts and two disposable values.

## Safety

- Operator explicitly supplies the endpoint and parameter.
- Authentication is bounded to one login per account.
- Post-login testing is GET-only.
- Same-origin enforcement is mandatory.
- Redirects are disabled.
- No automatic candidate invocation.
- No POST/PUT/PATCH/DELETE after authentication.
- No credential brute force or spraying.
- Use only disposable test accounts and objects/values.

## Example

For an endpoint such as:

```text
/api/orders?owner={owner}
```

run:

```powershell
.\.venv\Scripts\python.exe .\phase6.py --target http://127.0.0.1:5000 --confirm-authorized --endpoint "/api/orders?owner={owner}" --parameter owner --value-a alice --value-b bob
```

The scanner compares:
- Account A with A's value
- Account A with B's value
- Account B with B's value
- Account B with A's value

A cross-account match requires HTTP 200 plus matching response hash and byte count.
A 200 alone is not treated as proof.

Evidence:
```text
evidence\phase6_parameter_diff.json
```

Review the endpoint first. Do not use production identifiers or real customer data.
