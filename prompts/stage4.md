# Stage 4: Vulnerability Evaluation

You are performing **Stage 4** of an orchestrated network protocol security audit. Write your result to disk; do not print it in your response.

## Your Task

Evaluate one vulnerability finding from Stage 3.

- **Finding file**: `__FINDING_FILE_PATH__`
- **Output file**: `__OUTPUT_PATH__` (write here ONLY if the vulnerability is confirmed and severity ≥ Medium)

## Workflow

### Step 1: Read the Finding File

Read `__FINDING_FILE_PATH__`. It contains one vulnerability finding with location, vulnerability class, root cause, preliminary severity, a code snippet, and reachability notes. The file also includes source context (module, entry point, target project path).

### Step 2: Verify Existence (False-Positive Check)

Read the relevant source code at the target project path. Perform an in-depth analysis:
- Is the vulnerability reachable from attacker-controlled input?
- Are there any mitigating conditions that make exploitation impossible?
- Is the code path actually executed in the context described?

**If this is a false positive:** do NOT write any output file. The orchestrator will treat a missing output file as "filtered." Your task is complete — stop here.

### Step 3: Assess Impact and Severity

If the vulnerability is real, analyze its security impact:
- Determine what an attacker can achieve (RCE, DoS, info-leak, auth bypass, etc.)
- Compute a CVSS v3.1 base score
- Assign severity based on CVSS score:
  - **Critical**: 9.0–10.0
  - **High**: 7.0–8.9
  - **Medium**: 4.0–6.9
  - **Low**: 0.1–3.9

**If severity is below Medium:** do NOT write any output file. Your task is complete — stop here.

### Step 4: Write Evaluation Result

Write your evaluation to `__OUTPUT_PATH__`. Use **exactly** this format:

```markdown
### Summary JSON Line

```json
{
  "id": "TBD",
  "title": "...",
  "location": "file:function (lines X-Y)",
  "cwe_id": ["CWE-XXX"],
  "vulnerability_class": ["class1", "class2"],
  "cvss_score": "X.X",
  "severity": "Critical|High|Medium|Low"
}
```

### Detail

- **ID**: TBD
- **Title**: (short summary)
- **Location**: (file path + function name + line numbers)
- **Vulnerability class**: (e.g., "integer overflow leading to heap buffer overflow")
- **CWE ID**: (e.g., CWE-122, CWE-190)
- **Pre-requisites**: (specific compile features or run-time configuration required)
- **Impact**: (RCE / DoS / info-leak / auth bypass / etc.)
- **Severity**: (Critical / High / Medium / Low — must match JSON severity)
- **Code snippet**: (paste the relevant lines with inline comments explaining the root cause and trigger path)
```

**IMPORTANT**: The `"id"` in the JSON and the `**ID**` in the Detail section must both be `TBD`. The orchestrator will assign the real ID after all evaluations complete.

**IMPORTANT**: The output file MUST be parseable by `validate_stage4.py`. The JSON must be valid (no trailing commas, properly quoted strings).

## Completion Checklist

- [ ] Finding file read and source code verified
- [ ] False-positive check performed
- [ ] If confirmed: severity ≥ Medium and output written to `__OUTPUT_PATH__`
- [ ] If false positive or < Medium: no output file written
