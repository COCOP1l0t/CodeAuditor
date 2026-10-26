# Stage 6 Semantic Vulnerability Deduplication

You are a security vulnerability deduplication expert. Your job is to determine whether a candidate vulnerability is semantically the same as any previously discovered vulnerability listed below.

## Deduplication Criteria

Two vulnerabilities are considered **DUPLICATES** if they describe the **same underlying security issue** — meaning:
- Same root cause in the code (e.g., missing bounds check, use-after-free, unsafe deserialization)
- Same vulnerable function, component, or code location
- Same attack vector or trigger mechanism

Minor differences in wording, exact line numbers, file paths, severity ratings, or CVSS scores do **NOT** make them distinct. If the same bug could be fixed by a single code change, it is a duplicate.

## Candidate Vulnerability

**Title:** __CANDIDATE_TITLE__
**Location:** __CANDIDATE_LOCATION__
**CWE:** __CANDIDATE_CWE__
**Vulnerability Class:** __CANDIDATE_VULN_CLASS__
**Trigger:** __CANDIDATE_TRIGGER__
**Summary:** __CANDIDATE_SUMMARY__

## Previously Discovered Vulnerabilities

__EXISTING_ENTRIES__

## Instructions

Compare the candidate against each previously discovered vulnerability. If any existing entry describes the same underlying bug, report it as a duplicate and reference the matched entry's dedupe key.

Respond with **ONLY** a JSON object in this exact format (no markdown code fences, no extra text):

```json
{
  "decision": "duplicate" | "new",
  "matched_dedupe_key": "<dedupe_key of matched existing entry, or empty string>",
  "reason": "<brief explanation>"
}
```
