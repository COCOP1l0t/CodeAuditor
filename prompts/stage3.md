# Stage 3: Vulnerability Analysis

You are performing **Stage 3** of an orchestrated software security audit. Write your findings to disk; do not print them in your response.

## Your Assignment

Before starting analysis, read the auditing focus at `__AUDITING_FOCUS_PATH__` and the vulnerability criteria at `__VULN_CRITERIA_PATH__`. The auditing focus tells you which components deserve the closest scrutiny. The vulnerability criteria define what distinguishes a vulnerability from a bug. Use this context to focus your analysis on reachable, exploitable issues.

Read your analysis unit file at `__AU_FILE_PATH__`. It describes the codebase you are assigned to and provides the context you need to start your analysis.

### Scope of Your Analysis

The files listed in your analysis unit are your **starting point**, not a hard boundary. Begin your analysis there, but follow cross-file dependencies whenever your analysis requires it — for example, to understand a called function's behavior, verify whether input is sanitized upstream, trace data flow into a downstream consumer, or check assumptions about a dependency's contract.

Your primary focus remains the code and concerns described in the analysis unit. Do not exhaustively read unrelated modules — but do not stop at AU boundaries when tracing a relevant code path.

Your task: discover security bugs and vulnerabilities in the assigned codebase.

## Wiki Knowledge Base

__WIKI_CONTEXT__

## Output

For each confirmed vulnerability, write one JSON file to `__RESULT_DIR__/` named `__FINDING_PREFIX__-F-{NN}.json` (zero-padded: F-01, F-02, ...).

**Each finding file must contain a single JSON object with this exact structure:**

```json
{
  "finding_id": "F-01",
  "title": "Short descriptive title",
  "location": "file:function (lines X-Y)",
  "vulnerability_class": "e.g. buffer overflow, integer underflow, use-after-free",
  "root_cause": "Brief description",
  "preliminary_severity": "Critical|High|Medium|Low",
  "code_snippet": "5-30 lines of annotated code showing the vulnerability",
  "reachability_notes": "How an attacker reaches this, prerequisites"
}
```

**Format rules** (enforced by validator):
1. The file must contain valid JSON (no trailing commas, no comments).
2. Required keys: `finding_id`, `title`, `location`, `vulnerability_class`, `root_cause`, `preliminary_severity`, `code_snippet`.
3. `preliminary_severity` must be exactly one of: `Critical`, `High`, `Medium`, `Low`.
4. `finding_id` must match the `F-{NN}` pattern from the filename.
5. One finding per file.

**Do not report issues that require non-default configuration.** If a potential vulnerability can only be triggered when the software is compiled with a non-default build flag (32-bit compilation is considered a non-default configuration), feature gate, or `./configure` option, or when a non-default runtime configuration option is enabled, it is out of scope. Only report vulnerabilities that are reachable under default compilation and default runtime configuration.

If no vulnerabilities are found, write no files.
