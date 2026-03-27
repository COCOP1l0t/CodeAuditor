# ProtocolAuditor Rebuild Plan

## Context

The previous TypeScript implementation (preserved in `bak/`) used `@openai/codex-sdk` and Claude Code CLI as agent backends. We are rebuilding from scratch in **Python** based on `design.md`, keeping the proven architectural patterns from `bak/` while simplifying the stack.

## Key Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Language | Python 3.14 | User preference; simpler than TS for orchestration |
| Agent backend | `claude-code-sdk` (Python, already installed) | Native async Python SDK with `query()` and `ClaudeCodeOptions` |
| Concurrency | `asyncio.Semaphore` | stdlib — no external dependency needed |
| Prompt system | Markdown files with `__KEY__` substitution | Same as before, proven |
| Checkpoint/resume | File-based markers (`.markers/` directory) | Same as before |
| Validation | Per-stage validators with auto-repair loop | Same as before |
| Report generation | Deterministic Python (no agent) | Same as before |
| Testing | `pytest` | Standard Python testing |
| CLI | `argparse` | stdlib — no dependency needed |

## Architecture Overview

```
protocol_auditor/
├── __main__.py          # CLI entry point (argparse, config, run orchestrator)
├── config.py            # AuditConfig dataclass + defaults
├── orchestrator.py      # Sequential stage runner
├── agent.py             # claude-code-sdk wrapper + validation loop
├── prompts.py           # load_prompt() with __KEY__ substitution
├── checkpoint.py        # CheckpointManager (file + marker based)
├── logger.py            # Structured logger (stdlib logging)
├── utils.py             # run_parallel_limited, file helpers, severity sort
├── stages/
│   ├── __init__.py
│   ├── stage0.py        # Setup: create output dirs
│   ├── stage1.py        # Module decomposition
│   ├── stage2.py        # Scale assessment → analysis units
│   ├── stage3.py        # Bug discovery (per AU)
│   ├── stage4.py        # Threat model research
│   ├── stage5.py        # Vulnerability evaluation (per finding)
│   └── stage6.py        # Report generation (deterministic)
├── parsing/
│   ├── __init__.py
│   ├── stage1.py        # Parse module table from stage-1 output
│   ├── stage2.py        # Parse AU definitions from stage-2 drafts
│   └── stage3.py        # Parse finding files from stage-3 output
├── validation/
│   ├── __init__.py
│   ├── common.py        # Shared: read_file, find_section, parse_table, check_field
│   ├── stage1.py        # Validate module decomposition format
│   ├── stage2.py        # Validate AU definitions
│   ├── stage3.py        # Validate finding format
│   ├── stage4.py        # Validate threat model
│   └── stage5.py        # Validate evaluated findings (JSON + detail)
├── report/
│   ├── __init__.py
│   ├── generate.py      # Build report.md from stage-4 + stage-5 outputs
│   └── helpers.py       # File listing, section extraction
└── tests/
    └── test_parsers_and_report.py

prompts/
├── stage1.md
├── stage2.md
├── stage3.md
├── stage4.md
└── stage5.md

pyproject.toml           # Project config, dependencies, entry point
```

## SDK Integration

The `claude-code-sdk` Python package provides an async `query()` function:

```python
from claude_code_sdk import query, ClaudeCodeOptions

async def run_agent(prompt: str, cwd: str, add_dirs: list[str] | None = None) -> str:
    options = ClaudeCodeOptions(
        allowed_tools=["Read", "Glob", "Grep", "Write", "Edit", "Bash"],
        permission_mode="bypassPermissions",
        max_turns=50,
        cwd=cwd,
        add_dirs=add_dirs or [],
    )
    text_parts: list[str] = []
    async for message in query(prompt=prompt, options=options):
        if message.type == "assistant" and hasattr(message, "content"):
            for block in message.content:
                if hasattr(block, "text"):
                    text_parts.append(block.text)
    return "\n".join(text_parts)
```

Key `ClaudeCodeOptions` fields we use:
- `allowed_tools` — whitelist of tools the agent can use
- `permission_mode` — `"bypassPermissions"` for unattended operation
- `max_turns` — limit agent loop iterations
- `cwd` — working directory for the agent
- `add_dirs` — additional directories the agent can access (for output dirs, reference files)

## Stage-by-Stage Implementation

### Stage 0: Setup

- Create output directory tree: `.markers/`, `stage-2-details/`, `stage-3-details/`, `stage-4-details/`, `stage-5-details/`, `stage-5-details/_pending/`
- No agent call — pure filesystem setup via `os.makedirs()`

### Stage 1: Module Decomposition

- **Input**: Target project path
- **Agent call**: Single sub-agent reads the entire project, produces `stage-1-modules.md`
- **Output format**: Markdown with "Project Summary" section + "Modules" table (`M-N` | Module Name | Description | Files)
- **Validation**: Check sections exist, table parses, IDs match `M-\d+`
- **Parser**: Extract `list[Module]` (dataclass) for stage 2

### Stage 2: Scale Assessment & Analysis Units

- **Input**: Module list from stage 1
- **Parallelism**: One sub-agent per module (`asyncio.Semaphore(max_parallel)`)
- **Agent call**: Each agent reads its assigned files, writes a draft to `stage-2-details/{MODULE_ID}.md`
- **Draft format**: Either single `### AU:` block or split `### AU-P{N}:` blocks, each with Module Name / Description / Files / Focus fields
- **Validation**: Check block format, required fields, no blank placeholders
- **Post-processing (orchestrator)**: Parse all drafts → assign globally unique AU IDs → write final `AU-{N}.md` files with structured context
- **Output**: `list[AnalysisUnit]` for stage 3

### Stage 3: Bug Discovery

- **Input**: Analysis unit files from stage 2
- **Parallelism**: One sub-agent per AU (semaphore-limited)
- **Agent call**: Each agent reads AU file + source files, writes findings to `stage-3-details/{AU_PREFIX}-F-{NN}.md`
- **Finding format**: `### F-{NN}: {Title}` with Location / Vulnerability Class / Root Cause / Preliminary Severity + code snippet
- **Validation**: One `### F-{NN}:` block per file, severity in {Critical, High, Medium, Low}, all required fields present
- **Output**: List of all finding file paths

### Stage 4: Threat Model Research

- **Input**: Target project path, stage-1 output for context
- **Agent call**: Single sub-agent with web search + git log access
- **Tasks**: Search SECURITY.md, git history for security fixes, project website, CVE databases
- **Output**: Two files:
  - `stage-4-threat-model.md` — Project Summary + Threat Model sections
  - `stage-4-details/instruction-stage5.md` — Severity assessment guidance
- **Validation**: Required sections exist

### Stage 5: Vulnerability Evaluation

- **Input**: Stage 3 findings + stage 4 severity guidance
- **Parallelism**: One sub-agent per finding (semaphore-limited)
- **Agent call**: Each agent reads finding + guidance, evaluates:
  1. Is this a real issue (not false positive)?
  2. Does it qualify as a security vulnerability?
  3. What severity? (must be >= Medium to keep)
- **Output (if confirmed)**: File in `stage-5-details/_pending/{name}.md` with "Summary JSON Line" section (JSON with id/title/location/cwe_id/vulnerability_class/cvss_score/severity) + "Detail" section
- **Output (if rejected)**: No file written (`skip_if_missing` validation)
- **Post-processing (orchestrator)**: Scan `_pending/`, assign severity-prefixed IDs (C-01, H-01, M-01, L-01...), move to `stage-5-details/`, inject IDs into file content
- **Validation**: JSON structure, required keys, severity value

### Stage 6: Report Generation

- **No agent** — deterministic Python
- **Input**: `stage-4-threat-model.md` + all `stage-5-details/*.md` files
- **Output**: `report.md` with:
  - Project Summary (from stage 4)
  - Threat Model (from stage 4)
  - Findings Overview (severity counts)
  - Findings Summary (markdown table sorted by severity → ID)
  - Detailed Findings (full detail per finding)

## Implementation Order

### Phase 1: Project Skeleton & Infrastructure

1. **`pyproject.toml`** — Dependencies: `claude-code-sdk`, `pytest`. Entry point: `protocol-auditor` → `protocol_auditor.__main__:main`.
2. **`protocol_auditor/config.py`** — `AuditConfig` dataclass: `target`, `output_dir`, `max_parallel` (4), `threat_model`, `scope`, `skip_stages`, `resume`, `log_level`.
3. **`protocol_auditor/logger.py`** — Thin wrapper around `logging` stdlib, writes to stderr.
4. **`protocol_auditor/utils.py`** — `run_parallel_limited()` (asyncio.Semaphore + gather), `list_markdown_files()`, `list_matching_files()`, `compare_severity_then_id()`.
5. **`protocol_auditor/prompts.py`** — `load_prompt(name, substitutions)`: read `prompts/{name}.md`, replace `__KEY__` placeholders.
6. **`protocol_auditor/checkpoint.py`** — `CheckpointManager` with file-based and marker-based detection, `is_complete()` + `mark_complete()`.
7. **`protocol_auditor/validation/common.py`** — `read_file_or_issues()`, `find_section()`, `parse_markdown_table_rows()`, `check_field()`, `strip_json_comments()`, `strip_code_fence()`.

### Phase 2: Agent Wrapper

8. **`protocol_auditor/agent.py`** — Claude Code SDK integration:
   - `run_agent(prompt, cwd, add_dirs, max_turns)` → `str`: async wrapper around `query()`
   - `run_with_validation(prompt, cwd, validate_fn, max_retries, skip_if_missing)` → run → validate → retry with repair prompt

### Phase 3: Stages (in order)

9. **`protocol_auditor/stages/stage0.py`** — `os.makedirs()` for directory tree
10. **Stage 1**: `stages/stage1.py` + `parsing/stage1.py` + `validation/stage1.py` + `prompts/stage1.md`
11. **Stage 2**: `stages/stage2.py` + `parsing/stage2.py` + `validation/stage2.py` + `prompts/stage2.md`
12. **Stage 3**: `stages/stage3.py` + `parsing/stage3.py` + `validation/stage3.py` + `prompts/stage3.md`
13. **Stage 4**: `stages/stage4.py` + `validation/stage4.py` + `prompts/stage4.md`
14. **Stage 5**: `stages/stage5.py` + `validation/stage5.py` + `prompts/stage5.md`
15. **Stage 6**: `stages/stage6.py` + `report/generate.py` + `report/helpers.py`

### Phase 4: Orchestrator & CLI

16. **`protocol_auditor/orchestrator.py`** — `async run_audit(config)`: sequential stage calls with skip/resume logic
17. **`protocol_auditor/__main__.py`** — `argparse` CLI: `--target`, `--output-dir`, `--max-parallel`, `--threat-model`, `--scope`, `--skip-stages`, `--resume`, `--log-level`. Calls `asyncio.run(run_audit(config))`.

### Phase 5: Tests

18. **`tests/test_parsers_and_report.py`** — `pytest` tests for parsers, validators, and report generation

## Key Data Types

```python
@dataclass
class Module:
    id: str          # "M-1", "M-2", ...
    name: str
    description: str
    files: list[str]

@dataclass
class AnalysisUnit:
    id: str          # "AU-1", "AU-2", ...
    module_id: str
    name: str
    description: str
    files: list[str]
    focus: str

@dataclass
class Finding:
    id: str          # "C-01", "H-01", etc. (assigned in stage 5)
    title: str
    location: str
    cwe_id: str
    vulnerability_class: str
    cvss_score: float
    severity: str    # Critical, High, Medium, Low
    detail: str      # Full markdown detail
```

## Changes from Previous Implementation

| Area | Old (`bak/`, TypeScript) | New (Python) |
|------|--------------------------|--------------|
| Language | TypeScript + Node.js ESM | Python 3.14 |
| Agent backend | CLI spawn (`claude --print`) + Codex SDK | `claude-code-sdk` Python package (`query()`) |
| Concurrency | `p-limit` / manual Promise pool | `asyncio.Semaphore` + `asyncio.gather` |
| CLI parsing | Custom arg parsing | `argparse` stdlib |
| Testing | Node built-in test runner | `pytest` |
| Type system | TypeScript interfaces | `dataclasses` + type hints |
| Package management | npm / package.json | pip / pyproject.toml |
| Logging | Custom leveled logger | stdlib `logging` |

## Output Directory Layout

```
{output_dir}/
├── .markers/
│   ├── stage2-M-1, stage2-M-2, ...
│   ├── stage3-AU-1, stage3-AU-2, ...
│   └── stage5-{name}, ...
├── stage-1-modules.md
├── stage-2-details/
│   ├── M-1.md, M-2.md, ...        (drafts from agents)
│   ├── AU-1.md, AU-2.md, ...      (final AU files from orchestrator)
├── stage-3-details/
│   ├── AU-1-F-01.md, AU-1-F-02.md, ...
├── stage-4-threat-model.md
├── stage-4-details/
│   └── instruction-stage5.md
├── stage-5-details/
│   ├── _pending/                   (temp before ID assignment)
│   ├── C-01.md, H-01.md, ...      (final, severity-prefixed)
└── report.md
```
