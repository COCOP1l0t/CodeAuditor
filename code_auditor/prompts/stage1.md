# Stage 1: Security Context Research

You are performing a stage of an orchestrated software security audit. Write your output to disk; do not print it in your response.

## Your Task

Research the project at **__TARGET_PATH__** and produce three documents:
1. A **research record** capturing all security-relevant findings from your research (used as input for generating the directives below).
2. An **auditing focus** directive identifying which modules and components are most vulnerability-productive (injected into bug discovery agents).
3. A **vulnerability criteria** directive defining the boundary between bugs and vulnerabilities (injected into bug discovery and evaluation agents).

- **Output file (research record)**: `__OUTPUT_PATH__`
- **Output file (auditing focus)**: `__AUDITING_FOCUS_PATH__`
- **Output file (vulnerability criteria)**: `__VULN_CRITERIA_PATH__`
- **Today's date**: __TODAY__
- **Search window**: __START_DATE__ to __TODAY__ (recent 5 years)

## User Instructions

__USER_INSTRUCTIONS__

## Wiki Knowledge Base

__WIKI_CONTEXT__

## Workflow

### Step 1: Security Context Research

Investigate the project's security posture by collecting information from the following sources, in order of priority. You do not have to exhaust every source — stop when you have collected enough information to produce the outputs described below.

**Source tier 1:**
- Read `SECURITY.md` (or equivalent) carefully. Note the vulnerability disclosure process, scope statements, and critically, any links to external resources (security announcements page, bug bounty program, mailing lists).
- Usually the SECURITY.md or other docs link to a **project website**, a **security announcements page**, or a **bug bounty program**, and you **must** visit and collect information from them carefully.

**Source tier 2:(optional)**
- Search git history for security-relevant commits: keywords "CVE", "security", "fix", "vulnerability", "overflow", "injection", "bypass", "DOS", "crash", "patch", etc.

**Source tier 3 (fallback only):**
- Search the Internet for CVEs, security advisories, and vulnerability reports associated with this project.
- Check for fuzzing infrastructure (`fuzz/`, `oss-fuzz/`, `tests/fuzz*`, etc.).
- Check `oss-security@lists.openwall.com` archives if the project is an open-source systems project.
- Check NVD, OSV.dev, and GitHub Advisory Database.
- For widely-packaged projects, check distro security trackers (Debian, Red Hat) website.

**Important**: Only consult tier 2 and 3 sources if tiers 1 yields insufficient information. Tier 2 and 3 are not a default step.

**Information to collect:**
- **Scope announcements** (from tier 1 only): Which functional modules and issue types are explicitly declared in or out of vulnerability scope by the project.
- **Historical vulnerabilities** (from tiers 1, 2, and 3): For each finding, record: CVE ID (if any), date, affected module/component, vulnerability class, root cause, impact, severity, and attacker profile (attack vector, prerequisites, network position).

### Step 2: Write Research Record

Write to **__OUTPUT_PATH__**. This file is a structured record of all findings from Step 1. It serves as the evidence base from which the auditing directives in Step 3 are derived.

Use this JSON structure:

```json
{
  "project": {
    "name": "",
    "path": "__TARGET_PATH__",
    "language": "",
    "description": "",
    "deployment_model": ""
  },
  "sources_consulted": [
    {
      "source": "",
      "url_or_path": "",
      "tier": 1,
      "notes": ""
    }
  ],
  "scope_announcements": {
    "in_scope_modules": [""],
    "out_of_scope_modules": [""],
    "in_scope_issue_types": [""],
    "out_of_scope_issue_types": [""],
    "raw_quotes": [""]
  },
  "historical_vulnerabilities": [
    {
      "cve_id": "",
      "date": "",
      "affected_component": "",
      "vulnerability_class": "",
      "root_cause": "",
      "impact": "",
      "severity": "",
      "attacker_profile": "",
      "summary": ""
    }
  ],
  "fuzzing_targets": [""],
  "notes": ""
}
```

Fields may be empty or omitted if no relevant information was found, but do not fabricate data. Record `raw_quotes` where possible so the directives can be grounded in primary sources.

### Step 3: Write Auditing Directives

From the research record, draw conclusions and write two separate directive files. Each directive will be selectively injected into the context of downstream analysis agents. They must be **concise and actionable** — generic security advice wastes context budget. Be specific to this project. Every claim in a directive should be traceable to a finding in the research record.

**Important**: Do not include commit hashes or CVE IDs in the directives. They provide no value in the context of the auditing process. Write only actionable conclusions.

#### Directive 1: Auditing Focus

Write to **__AUDITING_FOCUS_PATH__**.

Identify which modules, components, and code paths are most vulnerability-productive and deserve the closest scrutiny during bug discovery.

Structure:

```markdown
# Auditing Focus

## Explicit In-Scope and Out-of-Scope Modules

{List any modules or code areas that the project explicitly declares in or out of scope for vulnerability reports. If the project has no explicit scope statement, state that and move on.}

## Historical Hot Spots

{Which vulnerability classes cluster in which components, derived from historical CVEs and security fixes. Example:
- Buffer overflows cluster in the ASN.1 parsing code
- Use-after-free bugs cluster in the connection state machine

If no historical data is available, leave this section empty.}
```

#### Directive 2: Vulnerability Criteria

Write to **__VULN_CRITERIA_PATH__**.

Define the boundary between bugs and vulnerabilities to help analysis agents decide whether a given bug crosses the line into a security vulnerability.

**Guidelines for writing this directive:**
- If the project provides explicit scope guidelines (especially out-of-scope declarations), these take highest priority. All explicit guidelines must be carefully understood and included in the directive.
- If the project's explicit criteria are comprehensive enough to define the bug/vulnerability boundary, omit the Historical Calibration section entirely.
- If a Historical Calibration section is needed, derive it strictly from the project's historical vulnerability data. Be concise. Summarize: (1) the types of issues that have historically been classified as vulnerabilities, and (2) the attacker profile (attack vector, prerequisites, network position) that characterizes past vulnerabilities.

Structure:

```markdown
# Vulnerability Criteria

## Explicit In-Scope and Out-of-Scope Issue Types

{List any issue types that the project explicitly declares in or out of scope for vulnerability reports. Example:
- In scope: memory corruption, authentication bypass, remote code execution
- Out of scope: denial of service requiring local access, issues in test code
If the project has no explicit scope statement, state that and move on.}

## Historical Calibration

{Omit this section if explicit criteria above are comprehensive enough.

Otherwise, summarize from the project's historical vulnerability data:

1. Issue types that have historically been classified as vulnerabilities in this project. Example:
   - Heap buffer over-read in protocol parser → vulnerability (availability + info leak)
   - NULL pointer dereference in error path reachable from network → vulnerability (availability)
   - Off-by-one in internal utility not reachable from external input → not a vulnerability

2. Attacker profile: the typical attack vector, prerequisites, and network position of past vulnerabilities.

If no historical data is available, leave this section empty.}
```

## Completion Checklist

- [ ] SECURITY.md (or equivalent) read; links followed to project websites
- [ ] Security announcements page visited (if available)
- [ ] Bug bounty scope collected (if available)
- [ ] Security history researched (git log, CVEs, advisories; tier 3 sources only if tier 1-2 were sparse)
- [ ] Research record written to `__OUTPUT_PATH__` with all findings
- [ ] Auditing focus directive written to `__AUDITING_FOCUS_PATH__`
- [ ] Vulnerability criteria directive written to `__VULN_CRITERIA_PATH__`
