# ProtocolAuditor

An SDK-based orchestrator for automated network protocol security audits. Built on
[`claude-code-sdk`](https://github.com/anthropics/claude-code-sdk-python), it runs a
structured 5-stage pipeline where deterministic Python handles parsing, routing,
concurrency, and validation — while Claude sub-agents focus purely on security analysis.

## Why this exists

The original skill-based approach assigned an entire source module (with many entry
points) to a single Claude sub-agent. On any non-trivial codebase this overflows the
context window, degrading both analysis quality and output format compliance.

This orchestrator fixes that by decomposing Stage 3 into **one agent per entry point**,
and Stage 4 into **one agent per finding**. The fan-out is bounded by a configurable
concurrency cap and the pipeline is fully resumable via a checkpoint file.

## Prerequisites

- Claude Code CLI installed and authenticated (`claude --version`)
- Python ≥ 3.11

## Installation

```bash
git clone --recurse-submodules https://github.com/COCOP1l0t/ProtocolAuditor.git
cd ProtocolAuditor
pip install -e .
```

> The `--recurse-submodules` flag is required to pull the `audit-network-protocol/`
> submodule (validation scripts and security checklists).

## Usage

```
protocol-auditor --target PATH [options]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--target PATH` | *(required)* | Root directory of the project to audit |
| `--output-dir PATH` | `{target}/audit-output` | Where to write all stage outputs |
| `--max-parallel N` | `4` | Max concurrent agents |
| `--resume` | — | Resume from a previous checkpoint |
| `--threat-model TEXT` | network attacker with full packet control | Override the threat model fed to Stage 1 |
| `--scope TEXT` | — | Additional scope constraints for Stage 1 |
| `--skip-stages LIST` | — | Comma-separated stages to skip, e.g. `1,2` |
| `--skill-dir PATH` | auto-detected | Path to `audit-network-protocol/` if not a submodule |
| `--log-level LEVEL` | `INFO` | `DEBUG` / `INFO` / `WARNING` / `ERROR` |

### Examples

```bash
# Full audit
protocol-auditor --target ~/projects/my-dhcp-server

# Resume an interrupted run
protocol-auditor --target ~/projects/my-dhcp-server --resume

# Limit concurrency, custom output dir
protocol-auditor --target ~/projects/my-dns-impl \
  --max-parallel 2 \
  --output-dir /tmp/dns-audit

# Re-run only evaluation and report (stages 4–5), reusing existing analysis
protocol-auditor --target ~/projects/my-dns-impl \
  --skip-stages 1,2,3 \
  --output-dir /tmp/dns-audit
```

## Pipeline

```
Stage 0  Setup          — create output directories, initialise checkpoint
Stage 1  Scope          — one agent: orient, threat model, identify modules
Stage 2  Entry points   — one agent per module: enumerate EPs (parallel)
Stage 3  Analysis       — one agent per entry point: find vulnerabilities (parallel)
Stage 4  Evaluation     — one agent per finding: verify + CVSS score (parallel)
                          ↳ post-eval: filter FPs, assign IDs (C-01, H-01…), rename files
Stage 5  Report         — deterministic: merge Stage 4 findings into final report.md
```

Stages 2–4 run with `asyncio.Semaphore(max_parallel)` to bound concurrency.
Each agent output is validated by a dedicated script; failed validations trigger up to 2
repair retries before the finding is logged and skipped.

## Output structure

```
{output_dir}/
├── .checkpoint.json          # resume state
├── stage-1-scope.md          # threat model + in-scope modules
├── stage-2-details/
│   └── M-{N}.md              # entry points per module
├── stage-3-details/
│   └── M-{N}-EP-{N}-F-{NN}.md  # one finding per file
├── stage-4-details/
│   ├── _pending/             # temporary; cleaned up after ID assignment
│   └── {ID}.md               # C-01.md, H-01.md, M-01.md, L-01.md, …
└── report.md                 # final audit report
```

## Repository layout

```
ProtocolAuditor/
├── protocol_auditor/         # installable Python package
│   ├── main.py               # CLI (argparse)
│   ├── orchestrator.py       # pipeline controller
│   ├── agent_utils.py        # SDK wrapper, validation-retry loop, concurrency
│   ├── checkpoint.py         # JSON-backed resume state
│   ├── config.py             # dataclasses: AuditConfig, Module, EntryPoint, Finding
│   ├── parsing/              # deterministic regex parsers (no LLM)
│   │   ├── stage1_parser.py  # stage-1-scope.md → list[Module]
│   │   └── stage2_parser.py  # M-{N}.md → list[EntryPoint]
│   ├── prompts/              # agent prompt templates (__PLACEHOLDER__ substitution)
│   │   ├── stage1.md … stage4.md
│   ├── reference -> ../audit-network-protocol/reference
│   └── stages/               # one module per pipeline stage
│       ├── stage0_setup.py … stage5_report.py
├── audit-network-protocol/   # git submodule
│   ├── reference/            # security checklists (C/C++, Go, Rust, managed)
│   └── script/               # validate_stage{1-4}.py, generate_report.py
├── skills/                   # Claude Code skill definitions
├── DESIGN.md                 # architecture decisions and design rationale
└── pyproject.toml
```

## Resuming after interruption

The checkpoint file (`.checkpoint.json`) tracks every completed task by key:

| Key pattern | Meaning |
|-------------|---------|
| `stage1` | Stage 1 complete |
| `stage2:M-{N}` | Entry point file for module N written |
| `stage3:M-{N}:EP-{N}` | All finding files for this EP written |
| `stage4:{filename}` | Evaluation for one Stage 3 finding complete |

On `--resume`, the orchestrator loads the checkpoint, skips completed tasks, and
re-parses already-written output files to reconstruct in-memory state.
