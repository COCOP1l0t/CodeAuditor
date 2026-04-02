# Stage 4: Vulnerability Evaluation

You are performing **Stage 4** of an orchestrated software security audit. Write your result to disk; do not print it in your response.

## Your Task

Evaluate one vulnerability finding from Stage 3.

- **Finding file**: `__FINDING_FILE_PATH__`
- **Output file**: `__OUTPUT_PATH__` (write here ONLY if the vulnerability is confirmed and CVSS >= 4.0)
- **Vulnerability criteria** (bug vs. vulnerability boundary + historical calibration): `__VULN_CRITERIA_PATH__`

## Workflow

### Step 1: Read the Finding File

Read `__FINDING_FILE_PATH__` (JSON). It contains one vulnerability finding with location, vulnerability class, root cause, preliminary severity, a code snippet, and reachability notes.

### Step 2: Verify Existence (False-Positive Check)

Read the relevant source code at the target project path. Perform an in-depth static analysis:
- Is the vulnerability reachable from attacker-controlled input?
- Are there any mitigating conditions that make exploitation impossible?
- Is the code path actually executed in the context described?

**If this is a false positive:** do NOT write any output file. The orchestrator will treat a missing output file as "filtered." Your task is complete -- stop here.

### Step 3: Assess Pre-Requisites

Before scoring severity, determine the exact conditions required to trigger the vulnerability:

- **Compile-time flags**: Is the vulnerable code path only compiled in when a non-default or rarely-used flag is set (e.g., `#ifdef ENABLE_LEGACY_FEATURE`, an optional CMake/configure flag not enabled in typical builds)?
- **Runtime configuration**: Does triggering the vulnerability require a non-default configuration option that is unlikely to be enabled in real-world deployments?
- **Environment assumptions**: Does exploitation depend on an atypical deployment topology, hardware, or operating mode?

If the vulnerability requires a non-default compile flag or non-default runtime configuration that is uncommon in real-world deployments, cap its severity at **Medium** regardless of the theoretical impact. Document this constraint explicitly in the prerequisites field. The rationale: a vulnerability that most installations never expose is structurally less severe than one present in all default builds.

### Step 4: Assess Impact and CVSS Score

Read `__VULN_CRITERIA_PATH__` for project-specific vulnerability criteria: the bug-vs-vulnerability boundary and historical calibration.

Using this context together with your pre-requisite assessment, analyze the security impact:
- Determine what an attacker can achieve (RCE, DoS, info-leak, auth bypass, etc.)
- Compute a CVSS v3.1 base score (the orchestrator will derive the severity label from this score)
- If the non-default-config cap from Step 3 applies, cap the CVSS score at 6.9

**If the CVSS score is below 4.0:** do NOT write any output file. Your task is complete -- stop here.

### Step 5: Write Evaluation Result

Write your evaluation to `__OUTPUT_PATH__` as a single JSON object:

```json
{
  "id": "TBD",
  "title": "short summary",
  "location": "file:function (lines X-Y)",
  "cwe_id": ["CWE-XXX"],
  "vulnerability_class": ["class1", "class2"],
  "cvss_score": "X.X",
  "prerequisites": "specific compile flags, runtime configuration options, or deployment conditions required; note if non-default",
  "impact": "describe the output of triggering this vulnerability, how the security boundary is voilated",
  "code_snippet": "paste the relevant lines with inline comments explaining the root cause and trigger path"
}
```

**IMPORTANT**: The `"id"` field must be `"TBD"`. The orchestrator will assign the real ID after all evaluations complete.

**IMPORTANT**: The output file MUST be valid JSON (no trailing commas, no comments, properly quoted strings).

## Completion Checklist

- [ ] Finding file read and source code verified
- [ ] False-positive check performed
- [ ] Pre-requisites assessed (compile flags, runtime config, deployment assumptions)
- [ ] Vulnerability criteria read (`__VULN_CRITERIA_PATH__`)
- [ ] Non-default-config CVSS cap applied if applicable
- [ ] If confirmed and CVSS >= 4.0: output written to `__OUTPUT_PATH__` as valid JSON
- [ ] If false positive or CVSS < 4.0: no output file written
