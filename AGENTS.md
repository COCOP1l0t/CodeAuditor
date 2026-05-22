# CodeAuditor Agent Notes

## Project Basics

- Python project, Python >=3.12, packaging via `pyproject.toml` and hatchling.
- CLI entrypoint: `code-auditor` -> `code_auditor.__main__:main`.
- Primary test command: `pytest -q`.
- The TUI backend uses `textual>=0.50`, `rich>=13.0`, and `click>=8.1`.

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
