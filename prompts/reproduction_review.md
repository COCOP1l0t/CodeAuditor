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
not historical output. Follow the normal Stage 6 report/email/package format;
keep ZIP members byte-identical to their local counterparts, exclude email.txt
and generated caches from the ZIP, and list every retained file in the manifest.
Do not create a disclosure draft for any other outcome.
