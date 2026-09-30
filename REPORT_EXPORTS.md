# Report Export and Sharing

Sentinel now produces three report artifacts after a normal assessment:

    reports/
    ├── report.html
    ├── report_portable.html
    ├── report.pdf
    ├── findings.json
    └── evidence_manifest.json

## Local interactive report

report.html is the full interactive report used during the assessment. It keeps the evidence directory as external assets and provides the tabbed UI:

- Overview
- Findings
- Coverage
- Evidence
- Remediation
- Execution

Open it locally:

    Start-Process .\\reports\\report.html

## Portable single-file HTML

report_portable.html is designed for sharing with another device.

The exporter embeds local visual evidence images directly into the HTML as data URIs. The recipient does not need your evidence directory to view embedded screenshots.

Copy only this file to another computer, phone, or tablet and open it in a modern browser. The report keeps the same tabs and filtering, while findings, coverage, remediation and execution data are embedded in the document.

Share portable reports only with authorized recipients because assessment evidence can be sensitive.

## PDF report

When Playwright/Chromium is available, Sentinel automatically renders the portable report to PDF.

The print stylesheet exposes all report tabs in the PDF, even though the interactive HTML normally displays one tab at a time. The PDF includes:

- overview and severity summary
- findings
- coverage matrix
- evidence gallery
- remediation
- execution metadata

If Chromium PDF rendering is unavailable, the scan still succeeds and the portable HTML is produced. Open report_portable.html and use the browser's Print -> Save as PDF.

## CLI output

A completed run now reports:

    Findings JSON: reports/findings.json
    Findings HTML: reports/report.html
    Portable HTML: reports/report_portable.html
    PDF report: reports/report.pdf

If PDF generation is unavailable:

    PDF report: not generated (open portable HTML and Print -> Save as PDF)

## Evidence behavior

The portable exporter embeds supported local image evidence:

- PNG
- JPEG/JPG
- WebP

It does not silently embed arbitrary non-image files. Raw JSON evidence remains represented in the report's embedded data model.

## Recommended workflow

1. Run the authorized assessment.
2. Review report.html locally.
3. Validate important findings.
4. Share report_portable.html for browser-based single-file delivery.
5. Share report.pdf for a fixed document/management handoff.
6. Keep raw evidence and findings.json in the secured engagement workspace.


## 4. XLSX penetration report — `penetration_report.xlsx`

The framework also creates a downloadable Excel workbook for sharing the assessment as a structured penetration report.

The workbook contains:

- **Executive Summary** — target, run metadata, totals and severity distribution.
- **Failed Issues** — one row per reported finding with issue ID, failed issue, severity, confidence, category, method, URL, evidence/proof, impact and remediation.
- **Evidence** — evidence inventory and file references.
- **Remediation** — corrective actions and validation steps.
- **Coverage** — browser/viewport execution results.

### Evidence images inside the sheet

When a finding has a captured screenshot, the image is inserted directly into the **Failed Issues** worksheet. The workbook therefore carries the visual proof with the issue instead of requiring the recipient to locate a separate screenshot folder.

The generated file is:

    reports/penetration_report.xlsx

It can be opened in Microsoft Excel, LibreOffice Calc, or compatible spreadsheet software.

