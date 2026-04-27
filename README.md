# CodeAuditor

A multi-stage, agentic code auditing pipeline that can run on the [Claude Code SDK](https://github.com/anthropics/claude-code-sdk-python) or the [Codex App Server Python SDK](https://github.com/openai/codex/blob/main/sdk/python/README.md). Given a target source tree, CodeAuditor researches project context, decomposes the codebase into analysis units, hunts for bugs, evaluates them as security vulnerabilities, reproduces them with a working PoC, and finally prepares a disclosure-ready report package.

CodeAuditor has discovered several CVEs in widely used open-source projects — see [Vulnerabilities found](#vulnerabilities-found) below.

## How it works

The audit runs as seven sequential stages. Each stage is driven by a prompt template in `prompts/` and executed by one or more backend agents. Outputs are validated, and on validation failure a repair prompt is sent (up to `max_retries`). Intermediate artifacts are written under the output directory; a `.markers/` folder tracks completed sub-tasks so runs can be resumed.

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
- A working [Claude Code](https://docs.claude.com/en/docs/claude-code) install for `--backend claude` (the SDK reuses its authentication)
- A working Codex CLI at `/usr/local/bin/codex` with `codex app-server` support and local Codex auth/session for `--backend codex`
- Git, plus whatever build tools the target project needs for Stage 5 reproduction

## Installation

```bash
git clone https://github.com/<owner>/CodeAuditor.git
cd CodeAuditor
pip install -e .
```

This exposes the `code-auditor` CLI entry point.

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
| `--backend` | Agent backend: `claude` or `codex` (default: `claude`). |
| `--model` | Backend model override. Claude defaults to `claude-sonnet-4-6`; Codex uses the local Codex config default unless specified. |
| `--target-au-count` | Target number of analysis units for Stage 2 (default: `10`). |
| `--log-level` | `DEBUG` \| `INFO` \| `WARNING` \| `ERROR` (default: `INFO`). |

Runs resume from checkpoint markers automatically — delete the output directory (or its `.markers/` subdirectory) to start a fresh audit.

### Example

```bash
code-auditor \
  --target ~/projects/libfoo \
  --output-dir ~/audits/libfoo \
  --max-parallel 4 \
  --log-level DEBUG
```

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
├── agent.py             # Backend wrappers + validation retry loop
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

Tests cover parsers and validators; they do not make real agent calls.

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

### [QEMU](https://gitlab.com/qemu-project/qemu)
- CVE-2026-7180

## Responsible use

CodeAuditor is intended for auditing code you own or have explicit permission to test, and for coordinated disclosure to upstream maintainers. Do not use it to target systems or projects without authorization.

**Important:** Before sending any vulnerability report to project maintainers, manually review the generated disclosure materials. Verify that the vulnerability is real, the severity assessment is accurate, and the proof-of-concept actually reproduces the issue. Automated findings may contain false positives or inaccuracies that could waste maintainers' time or damage your credibility.

## License

Apache License 2.0 — see [LICENSE](LICENSE) for details.

This software is provided for educational, research, and experimental purposes only. See the disclaimer at the top of the LICENSE file.
