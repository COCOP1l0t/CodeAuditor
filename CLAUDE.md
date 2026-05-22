# CodeAuditor

Multi-stage code auditing agent using `claude-code-sdk` (Python). Given a target project, it researches security context → decomposes the codebase into analysis units → findings → vulnerabilities → PoC reproduction → disclosure preparation.

## Codex SDK Guidance

Rechecked against the upstream Codex Python SDK README on 2026-05-21:
https://github.com/openai/codex/blob/main/sdk/python/README.md

- The current upstream SDK package is `openai-codex`, imported as `openai_codex`.
- Import the ergonomic client API from `openai_codex`, including `AsyncCodex`, `Codex`, `AppServerConfig`, and `ApprovalMode`.
- Import app-server value/event types from `openai_codex.types`, including `ReasoningEffort` and `SandboxPolicy`.
- `thread.run(...)` and `thread.turn(...).run()` return `TurnResult`; `final_response` can be `None`.
- Service tier in the current SDK is a string field. Use `"fast"` or `"flex"`; do not pass stale `"priority"` values or rely on the old generated `ServiceTier` enum.
- Published SDK builds pin an exact `openai-codex-cli-bin` runtime dependency with the same version as the SDK. Only pass `AppServerConfig(codex_bin=...)` when intentionally running a specific local `codex app-server` binary.

This repo's backend should prefer `openai_codex` when available and keep the legacy `codex_app_server` fallback only for environments that cannot install the current SDK yet. Before replacing the project dependency with upstream `openai-codex`, verify installation with a dry run in the target Python environment; on this Linux environment, the upstream `main` SDK at `c07f66c9ecca61531b12958537c76d3b1fffde72` still required `openai-codex-cli-bin==0.131.0a4`, which pip could not resolve for this platform.

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
#   --enable-timeout   Enable per-stage agent timeouts
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