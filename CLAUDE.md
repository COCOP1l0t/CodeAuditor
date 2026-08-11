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

# Required (unless --web or --repo-url)
#   --target           Root directory of the project to audit
#   --repo-url         Git URL cloned into ~/.code_auditor/repo/ and audited

# Common options
#   --output-dir       Output directory (default: ~/.code_auditor/results/{repo}/audit-output-{commit})
#   --wiki             Read-only LLM wiki knowledge base directory
#   --max-parallel     Max concurrent agents (default: 1)
#   --backend          Agent backend: claude | codex (default: claude)
#   --model            Model override (Claude default: claude-sonnet-4-6; Codex default: gpt-5.4)
#   --target-au-count  Target number of analysis units for stage 2 (default: -1 = no ceiling)
#   --tui              Launch the interactive TUI dashboard
#   --web              Launch the web UI (server settings: ~/.code_auditor/settings.json)
#   --host             Web UI bind host (default: 127.0.0.1)
#   --port             Web UI bind port (default: 8000)
#   --db               Audit history SQLite DB (default: ~/.code_auditor/audits.db)
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
- **Task failure surfacing**: Failed parallel sub-tasks are collected in `config.task_errors`; any failure marks the run `failed` with a summary in the `error` field. Agent error results (e.g. API 429 quota exhaustion) raise instead of passing silently, and non-retryable errors fail fast without retries. Web History offers Resume for cancelled, failed, and done-with-errors runs.
- **Model resolution**: The model id is resolved fresh on every agent call — explicit per-call model > local `~/.claude/settings.json` (`env.ANTHROPIC_MODEL`, PoC stages prefer `ANTHROPIC_DEFAULT_OPUS_MODEL`) > stored config value > built-in default (`config.resolve_agent_model` / `select_poc_model`). Models actually used accumulate in `config.models_used` and are persisted to the run's `models_used` column for the Web UI.
- **Usage accounting**: Every agent invocation's token usage and dollar cost (Claude `ResultMessage`, Codex `tokenUsage` events) accumulate in `config.usage_stats` via `utils.record_agent_usage()` and are persisted to the run's `usage_stats` JSON column; shown in Web History and the run detail page.
- **PoC worktree isolation**: Stage 5/6 agents run in a detached worktree (`{output}/.poc-worktree`, created by `repos.ensure_poc_worktree()`) so the shared repo mirror stays clean; web resume auto-stashes leftover mirror changes from older runs instead of failing on a dirty checkout
- **Checkpoint/resume**: `.markers/` directory tracks completed sub-tasks; `--resume` skips them
- **Parallel agents**: `utils.run_parallel_limited()` uses `asyncio.Semaphore` + `gather`
- **Output dir layout**: `{output}/stage{1-security-context,2-analysis-units,3-findings,4-vulnerabilities,5-pocs,6-disclosures}/`, `.markers/`
- **Web settings boundary**: backend/model/log level and managed paths come only from `~/.code_auditor/settings.json`; browser requests cannot override them
- **Logging tiers**: INFO is reserved for stage-level milestones (`Stage N: ...`); per-tool-call agent activity, subagent lifecycle, and per-file validation results log at DEBUG and always persist to the task's `agent.log` regardless of level
- **Web Wiki discovery**: optional Wikis are discovered from `~/.code_auditor/wiki/` and selected by opaque local name; `wiki_path` is not a Web config field
- **Disclosure storage boundary**: SQLite owns Disclosure metadata, review status, dedupe identity, and artifact indexes; Stage 5/6 reports remain filesystem artifacts and there is no registry-path setting

## Project layout

```
code_auditor/
├── __main__.py          # CLI (argparse) → asyncio.run(run_audit)
├── config.py            # AuditConfig, Module, AnalysisUnit, ValidationIssue dataclasses
├── disclosures.py       # Stable Disclosure identity + email metadata helpers
├── db.py                # SQLite audit history: AuditStore, schema, output-dir scanner,
│                        #   AU persistence/reuse (seed_analysis_units)
├── orchestrator.py      # Sequential stage runner
├── agent.py             # claude-code-sdk wrapper + validation retry loop
├── prompts.py           # load_prompt() with __KEY__ substitution
├── checkpoint.py        # File/marker-based checkpoint/resume
├── repos.py             # Git URL → ~/.code_auditor/repo/ mirror (clone + reuse)
├── logger.py            # stdlib logging wrapper
├── utils.py             # run_parallel_limited, file helpers, severity sort
├── stages/              # stage0–stage6 (one file per stage)
├── parsing/             # stage2.py — extract structured data from agent output
├── validation/          # common.py + stage1–stage6 — validate agent output format
├── web/                 # FastAPI web UI (--web): server.py endpoints, job.py single-job
│                        #   manager, progress.py EventBus/SSE + duck-typed tui reporter,
│                        #   static/ vanilla-JS page
└── tests/
prompts/                 # stage1.md–stage6.md — prompt templates with __KEY__ placeholders
```
