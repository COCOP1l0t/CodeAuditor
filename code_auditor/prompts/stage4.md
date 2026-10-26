# Stage 4: Vulnerability Evaluation

You are performing **Stage 4** of an orchestrated software security audit. Write your result to disk; do not print it in your response.

## Your Task

Evaluate one vulnerability finding from Stage 3.

- **Finding file**: `__FINDING_FILE_PATH__`
- **Output file**: `__OUTPUT_PATH__` (write here ONLY if the vulnerability is confirmed and CVSS >= 4.0)
- **Vulnerability criteria** (bug vs. vulnerability boundary + historical calibration): `__VULN_CRITERIA_PATH__`

## Wiki Knowledge Base

__WIKI_CONTEXT__

## Workflow

### Step 1: Read the Finding File

Read `__FINDING_FILE_PATH__` (JSON). It contains one vulnerability finding with location, vulnerability class, root cause, preliminary severity, a code snippet, and reachability notes.

### Step 2: Data-Flow Trace (False-Positive Check)

Read the relevant source code at the target project path. Before making any verdict, you **must** trace the complete data-flow path from attacker-controlled input to the vulnerability trigger point:

1. **Entry point**: Identify exactly where attacker-controlled data enters the system (network read, file parse, API parameter, environment variable, etc.). Also, you must ensure that this entry point is reasonably reachable by an attacker in a realistic scenario.
2. **Propagation**: Track the data through every function call, assignment, and transformation between entry and the vulnerable sink. For each hop, note: which variable carries the tainted data, what function passes it, and whether the data is copied, cast, truncated, or otherwise transformed.
3. **Neutralizing checks**: At each step in the propagation chain, look for checks, sanitizers, or validators that could prevent exploitation — bounds checks, allowlist filters, type enforcement, length limits, encoding normalization, etc. For each check found, determine whether it is sufficient to fully neutralize the vulnerability or whether it can be bypassed.
4. **Sink**: Confirm the tainted data reaches the security-sensitive operation described in the finding, in a form that triggers the vulnerability.

**If any step in the chain breaks** — the data is fully sanitized, a check provably blocks the attacker's input, or the code path is unreachable — this is a false positive. Do NOT write any output file. The orchestrator will treat a missing output file as "filtered." Your task is complete -- stop here.

**If the full chain holds**, proceed to Step 3. You will record this trace in the output (Step 6).

### Step 3: Assess Pre-Requisites

Before scoring severity, determine if there are non-default configurations required to trigger the vulnerability:

- **Compile-time flags**: Is the vulnerable code path only compiled in when a non-default or rarely-used flag is set (e.g., `#ifdef ENABLE_LEGACY_FEATURE`, an optional CMake/configure flag not enabled in typical builds)?
- **Runtime configuration**: Does triggering the vulnerability require a non-default configuration option that is unlikely to be enabled in real-world deployments?
- **Environment assumptions**: Does exploitation depend on an atypical deployment topology, hardware, or operating mode?

**how the attacker crafts malicious input is not a pre-requisite**

**IMPORTANT:** If the vulnerability requires a non-default compile flag or non-default runtime configuration, cap its severity at **Medium** regardless of the theoretical impact. Document this constraint explicitly in the prerequisites field.

**IMPORTANT:** If the vulnerability can only be triggered in an unrealistic atypical environment, e.g. missing NULL check after memory allocation which can only be triggered when the system is under extreme memory pressure, you should deem it a false positive.


### Step 4: Analyze Attacker Trigger

From the attacker's perspective, determine how this vulnerability would be triggered in practice:

1. **Malicious input**: What specific input must the attacker craft? Describe the payload structure, format, and any constraints.
2. **Delivery mechanism**: How does the attacker deliver this payload to the vulnerable entry point?.
3. **Interaction requirements**: Does triggering the vulnerability require any user interaction.

Summarize your analysis into a brief "trigger" description for inclusion in the output.

### Step 5: Assess Impact and CVSS Score

Read `__VULN_CRITERIA_PATH__` for project-specific vulnerability criteria: the bug-vs-vulnerability boundary and historical calibration.

Using this context together with your pre-requisite assessment, analyze the security impact:
- Determine what an attacker can achieve (RCE, DoS, info-leak, auth bypass, etc.)
- Compute a CVSS v3.1 base score (the orchestrator will derive the severity label from this score)
- If the non-default-config cap from Step 3 applies, cap the CVSS score at 6.9

**If the CVSS score is below 4.0:** do NOT write any output file. Your task is complete -- stop here.

### Step 6: Write Evaluation Result

Write your evaluation to `__OUTPUT_PATH__` as a single JSON object:

```json
{
  "id": "TBD",
  "title": "short summary",
  "location": "file:function (lines X-Y)",
  "data_flow_trace": {
    "entry_point": "where attacker-controlled data enters (e.g. file:function, network read, API parameter)",
    "propagation_chain": [
      "step 1: description of how data moves from entry to next function",
      "step 2: description of next transformation or pass-through"
    ],
    "neutralizing_checks": "checks encountered along the path and why they are insufficient, or 'none'",
    "sink": "the security-sensitive operation where tainted data triggers the vulnerability"
  },
  "cwe_id": ["CWE-XXX"],
  "vulnerability_class": ["class1", "class2"],
  "cvss_score": "X.X",
  "prerequisites": "specific compile flags, runtime configuration options, deployment conditions required, or 'none'",
  "trigger": "brief description of how the attacker triggers the vulnerability: what malicious input they craft and how it is delivered",
  "impact": "describe the output of triggering this vulnerability, how the security boundary is violated",
  "code_snippet": "paste the relevant lines with inline comments explaining the root cause and trigger path"
}
```

**IMPORTANT**: The `"id"` field must be `"TBD"`. The orchestrator will assign the real ID after all evaluations complete.

**IMPORTANT**: The output file MUST be valid JSON (no trailing commas, no comments, properly quoted strings).

## Completion Checklist

- [ ] Finding file read and source code verified
- [ ] Data-flow trace performed (entry point -> propagation -> neutralizing checks -> sink)
- [ ] Pre-requisites assessed (compile flags, runtime config, deployment assumptions)
- [ ] Attacker trigger analyzed (malicious input, delivery mechanism, interaction requirements)
- [ ] Vulnerability criteria read (`__VULN_CRITERIA_PATH__`)
- [ ] Non-default-config CVSS cap applied if applicable
- [ ] If confirmed and CVSS >= 4.0: output written to `__OUTPUT_PATH__` as valid JSON
- [ ] If false positive or CVSS < 4.0: no output file written
