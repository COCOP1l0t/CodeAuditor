# Plan: Integrate Deep Analysis into CodeAuditor

## Overview

Add a new **Stage 7 (Deep Analysis)** to the audit pipeline that performs in-depth verification and PoC development for Critical/High severity findings. Also add a standalone CLI mode to deep-analyze a single vulnerability on demand.

---

## Design Decisions

### Stage numbering
- **Stage 7** runs after Stage 6 (report generation). Stage 6 remains the deterministic report assembly step; Stage 7 is the optional deep-dive.
- Stage 7 is **skippable** via the existing `--skip-stages 7` mechanism.
- Stage 7 is **on by default** for all findings classified as Critical or High severity. It can be disabled via `--no-deep-analysis` flag or skipped via `--skip-stages 7`.

### Execution order
- **Sequential, not parallel.** Deep analysis findings are processed one at a time. Each finding involves building the project, running PoCs, and iterative debugging — these are heavyweight operations that benefit from sequential execution (avoids resource contention, port conflicts, build directory races).
- Each Critical/High finding gets its own agent invocation, executed in severity order (Critical first, then High).

### Standalone CLI mode
- New flag: `--analyze-finding <path>` — takes a path to a JSON file (Stage 5 finding format) or a plain-text vulnerability description file.
- When `--analyze-finding` is used, the tool skips the full pipeline and runs only the deep analysis workflow on that single finding.
- Combined with `--target` (still required — points to the project source code).

---

## File Changes

### 1. `code_auditor/config.py` — Extend AuditConfig

Add two fields:

```python
deep_analysis: bool = True           # Stage 7 on by default; disable with --no-deep-analysis
analyze_finding: str | None = None   # Path to single finding for standalone mode
```

### 2. `code_auditor/__main__.py` — New CLI flags

Add arguments:

```
--no-deep-analysis    Disable deep analysis (Stage 7) for Critical/High findings
--analyze-finding F   Run deep analysis on a single finding (path to JSON or text file);
                      standalone mode — bypasses the entire audit pipeline
```

Dispatch logic:
- If `--analyze-finding` is provided: validate `--target` is also set, then call `run_single_finding(config)` directly. This is a fully standalone workflow — the orchestrator and all pipeline stages are bypassed entirely. Pipeline-only flags (`--resume`, `--skip-stages`, `--no-deep-analysis`, `--scope`) are ignored.
- Otherwise: proceed with `run_audit(config)` as before.

### 3. `prompts/stage7.md` — Deep analysis prompt template

Adapt the skill's 6-step methodology into a prompt template. Key placeholders:

| Placeholder | Source |
|------------|--------|
| `__TARGET_PATH__` | Project root (for building/testing) |
| `__FINDING_JSON_PATH__` | Path to the Stage 5 finding JSON |
| `__FINDING_DETAIL__` | Serialized finding content (title, location, root cause, etc.) |
| `__OUTPUT_DIR__` | `PoC/{ID}/` directory for artifacts |

The prompt encodes the full 6-step workflow from the skill:
1. Confirm the vulnerability (re-read code, check guards, optional git history)
2. Design reproduction strategy (project type, build config, PoC design)
3. Environment setup (build project, create artifact dir, assess system impact)
4. Develop and run PoC (iterative, capture evidence)
5. Write technical report → `PoC/{ID}/report.md`
6. Write disclosure email + package artifacts → `PoC/{ID}/email.txt`, `PoC/{ID}/PoC.zip`

**Adaptation from the skill**: The skill is written as interactive instructions for Claude Code (with user checkpoints for manual intervention). The prompt must be restructured for autonomous agent execution:
- Remove "stop and ask the user" language — instead instruct the agent to write a `manual-steps.md` file if elevated privileges or risky operations are needed, then proceed with what it can do autonomously.
- Checkpoints become self-validation steps (agent verifies its own outputs before proceeding).
- The agent gets full tool access: Read, Glob, Grep, Write, Edit, Bash (needed for building, running PoCs).

### 4. `stages/stage7.py` — Stage implementation

Two public functions:

#### `run_stage7(config, finding_paths) -> list[str]`
Pipeline mode entry point.

```
1. Filter finding_paths to only Critical/High severity (read each JSON, check severity field)
2. Sort by severity (Critical first, then High)
3. For each qualifying finding, sequentially:
   a. Check checkpoint — skip if already completed
   b. Create output dir: {output_dir}/PoC/{finding_id}/
   c. Build agent prompt from prompts/stage7.md with finding details
   d. Run agent (streaming to stdout) — validator checks for report.md existence
   e. Mark checkpoint complete
4. Return list of PoC report paths
```

#### `run_single_finding(config) -> str`
Standalone mode entry point (called from `__main__.py` when `--analyze-finding` is used).

```
1. Read the finding file at config.analyze_finding
2. Detect format:
   - If valid JSON with expected fields (title, location, etc.) → use as structured finding
   - If plain text → wrap into a minimal finding structure with the text as description
3. Create output dir: {output_dir}/PoC/{finding_id or "manual"}/
4. Build agent prompt from prompts/stage7.md
5. Run agent (single invocation, not parallelized)
6. Return PoC report path
```

### 5. `validation/stage7.py` — Output validator

Validates the deep analysis output:

```python
def validate_stage7_output(poc_dir: str) -> list[ValidationIssue]:
    # Required: report.md exists and is non-empty
    # Required: at least one PoC file (poc.py, poc.c, poc.go, etc.)
    # Optional but checked: email.txt, PoC.zip
```

Light validation — the agent has significant autonomy in this stage. The validator ensures the minimum deliverables exist. No structural parsing of report.md (it's free-form markdown following the template in the prompt).

### 6. `checkpoint.py` — Add Stage 7 support

Add checkpoint key pattern:
- `"stage7:{finding_id}"` → checks for `PoC/{finding_id}/report.md`

This allows `--resume` to skip findings that already have completed deep analysis reports.

### 7. `orchestrator.py` — Wire Stage 7

After Stage 6:

```python
# Stage 7: Deep Analysis (on by default for Critical/High)
if config.deep_analysis and 7 not in config.skip_stages:
    log.info("Stage 7: Deep analysis of Critical/High findings")
    poc_reports = await run_stage7(config, final_finding_paths)
    log.info(f"Stage 7 complete: {len(poc_reports)} deep analysis reports")
```

### 8. `stages/stage0.py` — Create PoC directory

Add `PoC/` to the directory structure created in Stage 0 (only if `config.deep_analysis` is True or `config.analyze_finding` is set).

---

## Output Directory Layout (additions)

```
{output}/
├── ... (existing stage outputs) ...
├── report.md                          # Stage 6 output (unchanged)
└── PoC/                               # Stage 7 output (new)
    ├── C-01/
    │   ├── report.md                  # Technical report
    │   ├── poc.py                     # Clean PoC
    │   ├── poc_debug.py               # Development PoC (optional)
    │   ├── email.txt                  # Disclosure email
    │   ├── PoC.zip                    # Packaged artifacts
    │   └── manual-steps.md           # Manual intervention needed (if any)
    ├── H-01/
    │   └── ...
    └── H-02/
        └── ...
```

---

## Agent Configuration for Stage 7

Stage 7 agents run with **full unrestricted permissions**, equivalent to `claude --dangerously-skip-permissions`:

- `permission_mode="bypassPermissions"` — no tool approval prompts. The agent needs to freely build projects, execute arbitrary commands, run PoCs, and manage files without interruption.
- All tools enabled: Read, Glob, Grep, Write, Edit, Bash (unrestricted).

**Model**: Stage 7 uses **`claude-opus-4-6`** (hardcoded, not inherited from `config.model`). Deep analysis requires the most capable model for complex reasoning across code analysis, build debugging, and PoC development.

**Streaming**: Agent output is **streamed to stdout in real time** so the user can observe the agent's progress during the lengthy analysis process. In `agent.py`, Stage 7 calls use a streaming mode that prints `TextMessageBlock` content and tool use events as they arrive, before collecting the final result.

**Max turns**: No limit (`max_turns=None`). Deep analysis involves unpredictable iteration — build failures, debugging, PoC refinement — and a turn cap would produce incomplete results with no clean recovery. Let the agent run to completion or failure.

The agent's `cwd` should be set to `config.target` (the project root) so it can build and run the project directly.

---

## Standalone Mode Flow

```
code-auditor --target /path/to/project --analyze-finding /path/to/finding.json [--output-dir DIR]

1. Parse args → config with analyze_finding set
2. Create output dir if needed
3. Call run_single_finding(config)
4. Print path to generated PoC report
```

For plain-text input (not JSON):
```
code-auditor --target /path/to/project --analyze-finding /path/to/vuln-description.txt
```

The tool detects the format by attempting JSON parse first, falling back to plain-text wrapping.

---

## Implementation Order

1. `config.py` — add fields (trivial)
2. `prompts/stage7.md` — write the prompt template (adapt from skill)
3. `validation/stage7.py` — write validator
4. `stages/stage7.py` — implement `run_stage7()` and `run_single_finding()`
5. `checkpoint.py` — add stage7 checkpoint key
6. `stages/stage0.py` — add PoC dir creation
7. `orchestrator.py` — wire stage 7 into pipeline
8. `__main__.py` — add CLI flags and standalone dispatch
9. Tests — add parser/validator tests for stage 7

---

## Edge Cases

- **No Critical/High findings**: Stage 7 logs "no findings qualify for deep analysis" and returns empty list. Not an error.
- **Build failure**: Agent should document the failure in report.md and note that PoC could not be developed. Validator still passes if report.md exists.
- **System impact concern**: Agent writes `manual-steps.md` with required manual steps instead of executing risky operations. The pipeline continues (doesn't block).
- **`--analyze-finding` is a fully standalone workflow**: It completely bypasses the audit pipeline (stages 0–7). No orchestrator, no checkpoint system, no stage sequencing. It launches a single deep-analysis agent session directly — equivalent to running the deep-analysis skill in an interactive Claude Code session. The `--resume`, `--skip-stages`, `--no-deep-analysis`, and other pipeline flags are ignored when `--analyze-finding` is active.
- **`--skip-stages 7`**: Works with existing mechanism. If stage 7 is skipped in the pipeline, deep analysis is not run even if Critical/High findings exist.
