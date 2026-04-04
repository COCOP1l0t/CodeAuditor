# Stage 3 & Stage 4 Refinement: AU Boundary Relaxation and Data-Flow Tracing

## Problem Statement

Two observed issues in the current auditing pipeline:

1. **Stage 3 AU boundary restriction**: Analysis agents confine themselves to only the files listed in their assigned analysis unit. When a vulnerability requires understanding code outside the AU (e.g., a called function in another module, an upstream sanitizer, a downstream sink), the agent stops at the boundary instead of following the code path. AUs should serve as starting points and analytical anchors, not hard constraints on what files the agent may read.

2. **Stage 4 false positives from shallow analysis**: The false-positive check in stage 4 asks three high-level questions ("Is it reachable?", "Are there mitigating conditions?", "Is the path executed?") but does not require the agent to trace the actual data-flow path. This allows the agent to confirm vulnerabilities without verifying that attacker-controlled data actually propagates from entry to sink without being neutralized along the way.

## Decisions

- **Stage 3 fix**: Prompt-only change. No structural changes to AU format or stage 2 output. The agents already have full filesystem access via their tools; the issue is that the prompt implicitly scopes their attention to AU files.
- **Stage 4 fix**: Prompt change + output schema change + validation + report rendering. The agent must perform an explicit data-flow trace, and that trace must be captured as a structured field in the output JSON for auditability.
- **Stage 3 guardrail**: Soft guardrail. The prompt directs agents to start with AU files and follow cross-file dependencies when analysis requires it, but keeps the AU as the primary focus anchor.

## Change 1: Stage 3 Prompt — AU Boundary Relaxation

**File**: `prompts/stage3.md`

**Change**: Add a new section after "Read your analysis unit file at `__AU_FILE_PATH__`..." and before "Your task: discover security bugs...":

> ### Scope of Your Analysis
>
> The files listed in your analysis unit are your **starting point**, not a hard boundary. Begin your analysis there, but follow cross-file dependencies whenever your analysis requires it — for example, to understand a called function's behavior, verify whether input is sanitized upstream, trace data flow into a downstream consumer, or check assumptions about a dependency's contract.
>
> Your primary focus remains the code and concerns described in the analysis unit. Do not exhaustively read unrelated modules — but do not stop at AU boundaries when tracing a relevant code path.

No changes to stage 3 runner code, validation, or output format.

## Change 2: Stage 4 Prompt — Data-Flow Tracing Requirement

**File**: `prompts/stage4.md`

**Change**: Replace the current Step 2 ("Verify Existence (False-Positive Check)") with:

> ### Step 2: Data-Flow Trace (False-Positive Check)
>
> Read the relevant source code at the target project path. Before making any verdict, you **must** trace the complete data-flow path from attacker-controlled input to the vulnerability trigger point:
>
> 1. **Entry point**: Identify exactly where attacker-controlled data enters the system (network read, file parse, API parameter, environment variable, etc.).
> 2. **Propagation**: Track the data through every function call, assignment, and transformation between entry and the vulnerable sink. For each hop, note: which variable carries the tainted data, what function passes it, and whether the data is copied, cast, truncated, or otherwise transformed.
> 3. **Neutralizing checks**: At each step in the propagation chain, look for checks, sanitizers, or validators that could prevent exploitation — bounds checks, allowlist filters, type enforcement, length limits, encoding normalization, etc. For each check found, determine whether it is sufficient to fully neutralize the vulnerability or whether it can be bypassed.
> 4. **Sink**: Confirm the tainted data reaches the security-sensitive operation described in the finding, in a form that triggers the vulnerability.
>
> **If any step in the chain breaks** — the data is fully sanitized, a check provably blocks the attacker's input, or the code path is unreachable — this is a false positive. Do NOT write any output file. Your task is complete.
>
> **If the full chain holds**, proceed to Step 3.

Steps 3, 4, and 5 remain unchanged.

## Change 3: Stage 4 Output Schema — `data_flow_trace` Field

**File**: `prompts/stage4.md` (Step 5 JSON schema)

**Change**: Add `data_flow_trace` to the output JSON schema, after `location`:

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
  "prerequisites": "...",
  "impact": "...",
  "code_snippet": "..."
}
```

Field semantics:
- `entry_point` (string, required): Where attacker-controlled data enters.
- `propagation_chain` (array of strings, required): One string per hop in the data-flow chain.
- `neutralizing_checks` (string, required): Checks found and why they don't block exploitation, or "none".
- `sink` (string, required): The security-sensitive operation that is triggered.

## Change 4: Stage 4 Validator — Require `data_flow_trace`

**File**: `code_auditor/validation/stage4.py`

**Changes**:
- Add `"data_flow_trace"` to `_REQUIRED_KEYS` (ensures presence check).
- After the existing CVSS validation block, add a new block that validates the structure of `data_flow_trace`:
  - Must be a dict.
  - Must contain four keys: `entry_point`, `propagation_chain`, `neutralizing_checks`, `sink`.
  - `propagation_chain` must be a list (of strings).
  - Each missing or maltyped subfield produces its own `ValidationIssue`.

## Change 5: Report Generator — Render Data-Flow Trace

**File**: `code_auditor/report/generate.py`

**Change**: In `_format_finding_detail()`, after rendering existing fields and before the code snippet, add rendering for `data_flow_trace` if present:

```markdown
- **Data Flow**:
  - **Entry point**: <entry_point value>
  - **Propagation**:
    1. <propagation_chain[0]>
    2. <propagation_chain[1]>
    ...
  - **Neutralizing checks**: <neutralizing_checks value>
  - **Sink**: <sink value>
```

Graceful degradation: if `data_flow_trace` is missing (old stage 4 output), the section is omitted. No crash.

## Files Changed

| File | Nature of Change |
|------|-----------------|
| `prompts/stage3.md` | Add "Scope of Your Analysis" section |
| `prompts/stage4.md` | Replace Step 2 with data-flow tracing; add `data_flow_trace` to Step 5 schema |
| `code_auditor/validation/stage4.py` | Require and validate `data_flow_trace` with subfield checks |
| `code_auditor/report/generate.py` | Render `data_flow_trace` in finding detail; graceful skip if absent |

## Out of Scope

- No changes to stage 2 AU format or stage 2 prompt.
- No changes to stage 3 output format or validation.
- No changes to stage runner code, orchestrator, config, or checkpoint logic.
- No structural context injection (call graphs, dependency hints) into AUs — deferred to future work.
