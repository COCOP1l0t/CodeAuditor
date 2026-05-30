# CodeAuditor

Multi-stage code auditing agent using `claude-code-sdk` (Python). Given a target project, it researches security context → decomposes the codebase into analysis units → findings → vulnerabilities → PoC reproduction → disclosure preparation.

## Quick Reference

- **Language**: Python >=3.12
- **Package manager**: pip (uses `pyproject.toml`, hatchling backend)
- **Entry point**: `code-auditor` CLI → `code_auditor/__main__.py:main`
- **Agent backends**: Claude via `claude-code-sdk`; Codex via local Codex app server SDK

## Running

```bash
# Install (editable)
pip install -e .

# Run an audit
code-auditor --target /path/to/project [options]

# Required
#   --target           Root directory of the project to audit

# Common options
#   --output-dir       Output directory (default: {target}/audit-output-YYYYMMDD)
#   --discovered       Reproduced bugs HTML file (default: {target}/reproduced-bugs.html)
#   --wiki             Read-only LLM wiki knowledge base directory
#   --max-parallel     Max concurrent agents (default: 1)
#   --backend          Agent backend: claude | codex (default: claude)
#   --model            Model override (Claude default: claude-sonnet-4-6; Codex default: gpt-5.4)
#   --target-au-count  Target number of analysis units for stage 2 (default: 10)
#   --tui              Launch the interactive TUI dashboard
#   --log-level        DEBUG|INFO|WARNING|ERROR (default: INFO)
```

## Testing

```bash
pytest -q
```

Tests are in `code_auditor/tests/test_parsers_and_report.py` — parsers and validators only, no agent calls.

## Architecture (7 stages)

| Stage | What it does | Parallelism |
|-------|-------------|-------------|
| 0 | Git pull + create output dirs | None (pure fs) |
| 1 | Security context research (git, web, SECURITY.md) | Single agent |
| 2 | Decompose project into analysis units (AUs) | Single agent |
| 3 | Bug discovery per AU | 1 agent per AU |
| 4 | Evaluate findings: real vuln? severity? | 1 agent per finding |
| 5 | PoC reproduction: build, exploit, capture evidence | 1 agent per vuln |
| 6 | Disclosure: report, email, minimal PoC, zip package | 1 agent per vuln |

## Key patterns

- **Prompt templates**: `prompts/stageN.md` with `__KEY__` placeholders, loaded via `prompts.py:load_prompt()`
- **Directive injection**: Stage 1 produces auditing focus and vulnerability criteria directives; injected into Stage 2 (scope/hot-spots), Stage 3 (both), and Stage 4 (vuln criteria only)
- **Validation + retry**: Each agent output is validated; on failure, a repair prompt is sent (up to `max_retries`)
- **Checkpoint/resume**: `.markers/` directory tracks completed sub-tasks; `--resume` skips them
- **Parallel agents**: `utils.run_parallel_limited()` uses `asyncio.Semaphore` + `gather`
- **Output dir layout**: `{output}/stage{1-security-context,2-analysis-units,3-findings,4-vulnerabilities,5-pocs,6-disclosures}/`, `.markers/`

## Project layout

```
code_auditor/
├── __main__.py          # CLI (argparse) → asyncio.run(run_audit)
├── config.py            # AuditConfig, Module, AnalysisUnit, ValidationIssue dataclasses
├── orchestrator.py      # Sequential stage runner
├── agent.py             # claude-code-sdk wrapper + validation retry loop
├── prompts.py           # load_prompt() with __KEY__ substitution
├── checkpoint.py        # File/marker-based checkpoint/resume
├── logger.py            # stdlib logging wrapper
├── utils.py             # run_parallel_limited, file helpers, severity sort
├── stages/              # stage0–stage6 (one file per stage)
├── parsing/             # stage2.py — extract structured data from agent output
├── validation/          # common.py + stage1–stage6 — validate agent output format
└── tests/
prompts/                 # stage1.md–stage6.md — prompt templates with __KEY__ placeholders
```
