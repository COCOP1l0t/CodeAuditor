# CodeAuditor

A multi-stage, agentic code auditing pipeline with pluggable agent backends. CodeAuditor can run with the [Claude Code SDK](https://github.com/anthropics/claude-code-sdk-python) or the experimental Codex app-server Python SDK. Given a target source tree, it researches project context, decomposes the codebase into analysis units, hunts for bugs, evaluates them as security vulnerabilities, reproduces them with a working PoC, and finally prepares a disclosure-ready report package.

CodeAuditor has discovered several CVEs in widely used open-source projects — see [Vulnerabilities found](#vulnerabilities-found) below.

## How it works

The audit runs as seven sequential stages. Each stage is driven by a prompt template in `prompts/` and executed by one or more agent backend sessions. Outputs are validated, and on validation failure a repair prompt is sent (up to `max_retries`). Intermediate artifacts are written under the output directory; a `.markers/` folder tracks completed sub-tasks so runs can be resumed.

| Stage | What it does | Parallelism |
|-------|--------------|-------------|
| 0 | Git pull + create output directories | None |
| 1 | Security context research (git history, web, `SECURITY.md`) | Single agent |
| 2 | Decompose the project into analysis units (AUs) | Single agent |
| 3 | Bug discovery per analysis unit | 1 agent per AU |
| 4 | Evaluate findings: real vulnerability? severity? | 1 agent per finding |
| 5 | PoC reproduction: build, exploit, capture evidence | 1 agent per vulnerability |
| 6 | Disclosure: technical report, email, minimal PoC, zipped package | 1 agent per vulnerability |

Stage 1 produces two directives — an *auditing focus* and *vulnerability criteria* — that are injected into later stages so the whole pipeline stays aligned with the project's actual threat model.

## Requirements

- Python **3.12+**
- For the default backend: a working [Claude Code](https://docs.claude.com/en/docs/claude-code) install (the SDK reuses its authentication)
- For the Codex backend: a working `codex` binary and `codex-app-server-sdk` installation, or a local `codex-main/sdk/python` checkout passed with `--codex-sdk-path`
- Git, plus whatever build tools the target project needs for Stage 5 reproduction

## Installation

```bash
git clone https://github.com/<owner>/CodeAuditor.git
cd CodeAuditor
pip install -e .
```

This exposes the `code-auditor` CLI entry point.

For local Codex SDK development, install both projects into the same environment:

```bash
uv venv
uv pip install -e . -e ../codex-main/sdk/python
```

Or install the optional Codex dependency directly from the OpenAI Codex repository:

```bash
pip install -e ".[codex]"
```

## Usage

```bash
code-auditor --target /path/to/project [options]
```

### Common options

| Flag | Description |
|------|-------------|
| `--target` | **Required.** Root directory of the project to audit. |
| `--output-dir` | Output directory (default: `{target}/audit-output`). |
| `--max-parallel` | Max concurrent agents (default: `1`). |
| `--agent-backend` | Agent runtime backend: `claude-code` or `codex` (default: `claude-code`). |
| `--model` | Agent model to use (default: `claude-sonnet-4-6` for Claude Code, `gpt-5.4` for Codex). |
| `--target-au-count` | Target number of analysis units for Stage 2 (default: `10`). |
| `--log-level` | `DEBUG` \| `INFO` \| `WARNING` \| `ERROR` (default: `INFO`). |

Runs resume from checkpoint markers automatically — delete the output directory (or its `.markers/` subdirectory) to start a fresh audit.

Run `code-auditor --help` for backend-specific options, including Codex binary, SDK path, sandbox, network, and writable-root controls.

### Claude Code example

```bash
code-auditor \
  --target ~/projects/libfoo \
  --output-dir ~/audits/libfoo \
  --max-parallel 4 \
  --log-level DEBUG
```

### Codex example

```bash
code-auditor \
  --target ~/projects/libfoo \
  --output-dir ~/audits/libfoo \
  --agent-backend codex \
  --codex-bin /usr/local/bin/codex \
  --audit-only \
  --max-parallel 1 \
  --log-level DEBUG
```

The Codex backend starts a Codex app-server session per agent task. Transient stream, TLS, timeout, and network disconnect failures are retried. If a Codex turn finally completes with a failed status, the backend raises an error instead of silently treating the missing output as a filtered vulnerability; this prevents failed Stage 4 evaluations from being checkpointed as complete.

Codex currently works best from an ASCII-only workspace path. Some Codex stream metadata paths may fail when the repository path contains non-ASCII characters.

## Output layout

```
{output-dir}/
├── stage1-security-context/  # context research + auditing focus + vuln criteria
├── stage2-analysis-units/    # codebase decomposition
├── stage3-findings/          # per-AU bug findings
├── stage4-vulnerabilities/   # evaluated, confirmed vulnerabilities
├── stage5-pocs/              # PoCs + evidence
├── stage6-disclosures/       # disclosure reports, emails, zipped PoCs
└── .markers/          # checkpoint markers for --resume
```

## Project layout

```
code_auditor/
├── __main__.py          # CLI entry point
├── config.py            # AuditConfig and dataclasses
├── orchestrator.py      # Sequential stage runner
├── agent.py             # Backend selection + validation retry loop
├── agent_backends/      # Claude Code and Codex agent runtime adapters
├── prompts.py           # Prompt loader with __KEY__ substitution
├── checkpoint.py        # Marker-based checkpoint/resume
├── logger.py            # Logging helper
├── utils.py             # Parallelism + file helpers
├── stages/              # stage0 – stage6
├── parsing/             # Structured extraction from agent output
├── validation/          # Per-stage output validators
└── tests/
prompts/                 # stage1.md – stage6.md prompt templates
```

## Development

```bash
pytest                       # run all tests
pytest code_auditor/tests    # same thing
pytest -k stage2             # filter by name
```

Tests cover parsers, validators, and backend selection helpers; they do not make real agent calls.

## Vulnerabilities found

Vulnerabilities CodeAuditor has helped discover and disclose:

### [httpd](https://github.com/apache/httpd)
- CVE-2026-28780
- CVE-2026-34032

### [ImageMagick](https://github.com/ImageMagick/ImageMagick)
- CVE-2026-40312

### [libexif](https://github.com/libexif/libexif)
- CVE-2026-40385
- CVE-2026-40386

## Responsible use

CodeAuditor is intended for auditing code you own or have explicit permission to test, and for coordinated disclosure to upstream maintainers. Do not use it to target systems or projects without authorization.

## License

TBD.
