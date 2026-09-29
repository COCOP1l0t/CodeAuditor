# Latest-source Reproduction Review

You are reviewing a security vulnerability retest against an immutable, freshly
fetched source revision. Analyze the evidence; do not rerun a different target,
change the recorded outcome, or fabricate runtime evidence.

## Identity

- Project: `__PROJECT__`
- Vulnerability: `__TITLE__`
- Original audited commit: `__BASE_COMMIT__`
- Tested remote HEAD commit: `__TESTED_COMMIT__`
- Deterministic PoC outcome: `__OUTCOME__`

## Inputs

- Finding: `__FINDING_PATH__`
- Server-recorded result: `__RESULT_PATH__`
- Latest retest report and retained evidence: `__RETEST_REPORT_PATH__`
- Previous Disclosure/PoC directory: `__PREVIOUS_DISCLOSURE_PATH__`
- Pinned latest source: `__TARGET_PATH__`

Write every output below `__OUTPUT_DIR__`.

Compare the original claim, the current source, relevant source changes, the
portable PoC, and the observed result. A failed or stale harness is not proof of
a fix. Distinguish source-level remediation, harness drift, missing dependencies,
and an actually exercised runtime path. Never promote static inspection, a
successful build, or historical output into a fresh runtime reproduction.

Create `assessment.json` with exactly this shape:

```json
{
  "schema_version": 1,
  "outcome": "__OUTCOME__",
  "disposition": "still-vulnerable|likely-fixed|harness-stale|environment-blocked|false-positive-possible|unknown",
  "summary": "Concise current-source conclusion and its evidence boundary",
  "source_analysis": "Relevant code changes and why they do or do not address the root cause",
  "disclosure_update": "What should change in the Disclosure and what must remain qualified"
}
```

Also create `retest-report.md` containing the two commit identities, exact
commands actually evidenced by the Stage 5 report, observed result, source
analysis, limitations, and recommended Disclosure update.

If and only if the deterministic outcome is `reproduced`, create a refreshed
Disclosure package under `__OUTPUT_DIR__/disclosure-draft/`. It must contain
`report.md`, `email.txt`, executable `reproduce.sh`, `disclosure.zip`, and
`retain-manifest.json`. Base it on the newly observed evidence and tested commit,
not historical output. Keep ZIP members byte-identical to their local
counterparts, exclude email.txt and generated caches from the ZIP, and list every
retained file in the manifest. Do not create a disclosure draft for any other
outcome.

### Refreshed report.md — exact section contract

The refreshed `report.md` is the document that gets sent upstream, so it is held
to the Stage 6 disclosure format and is validated mechanically. Use exactly these
level-2 headings, in this order, with non-empty content under each:

`## Summary`, `## Why This Is a Security Issue`, `## Severity Assessment`,
`## Pre-requisites`, `## Security Impact`, `## Trigger`, `## Root Cause`,
`## Reproduction` (with nested `### Steps to Reproduce` and `### Observed Result`).
`## Why This Is a Security Issue` must be present and non-empty even though the
Stage 5 retest report does not contain that section.

The Stage 5 retest report is an internal artifact. Do not copy its metadata block
or its heading names into the draft:

- It carries an internal identifier line (for example `- **Finding ID**: C-02`).
  A disclosure report must contain **no** internal audit identifier anywhere: no
  `Finding ID`, `Audit ID`, `Vulnerability ID`, or `Internal ID` line, and no
  `C-01`/`H-02`-style token. Drop the line entirely — do not rename or reword it.
- Its `## Severity` heading must become `## Severity Assessment`.
- Its `## Reproduction Steps` heading must become `## Reproduction`, with the
  steps nested under `### Steps to Reproduce`.
- Remove internal workspace paths (`/home/.../.code_auditor/`, `/tmp/code-auditor/`,
  `stage4-vulnerabilities/`, `stage5-pocs/`, `stage6-disclosures/`).

Keep the CVSS v3.1 vector and the written numeric score consistent, keep the
report self-contained for a reader with no knowledge of the audit, and state
evidence boundaries explicitly rather than overclaiming.

Before finishing, self-check the draft: every heading above is present and
non-empty, the CVSS vector and score agree, no internal identifier or workspace
path remains, `email.txt` has a `Subject:` header and a blank line before the
body, `disclosure.zip` members match their local counterparts byte for byte, and
`retain-manifest.json` lists every retained file.
