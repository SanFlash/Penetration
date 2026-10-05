# Focused Security Evidence

Security browser evidence is intentionally different from responsive-layout evidence.

## Security findings

For Medium/High/Critical security findings, the evidence capture attempts to locate the actual visible failure UI before taking a screenshot.

Detection priority:

1. Semantic error containers such as `role=alert`, `aria-live`, `.error`, `.alert`, `.toast`, `.notification`, `.modal`, and error-named attributes/classes.
2. Visible DOM elements containing finding-specific evidence/title/parameter terms.
3. Error-language signals such as `failed`, `invalid`, `denied`, `forbidden`, `unauthorized`, `exception`, `not found`, and `server error`.

The detected element is scrolled into view and the screenshot is clipped to a bounded browser window around it. The screenshot includes:

- the detected error UI;
- a red rectangle;
- a `FAILED: <finding-id>` label;
- a red arrow pointing to the detected error;
- limited surrounding context.

The security capture never uses `full_page=True`.

If no reliable error UI exists, the framework records a viewport-only fallback and explicitly records that no focus was found. It does not fabricate an error region.

## Compatibility evidence

Responsive and overflow checks may continue to use broader viewport screenshots because their purpose is to document layout behavior rather than a single error message.

## Evidence metadata

Each security capture records `capture.mode`, `capture.focus_selector`, `capture.focus_text`, `capture.focus_keywords`, and the final `clip` rectangle in `evidence/security_browser_evidence.json`.
