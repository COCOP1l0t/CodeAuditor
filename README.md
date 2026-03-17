# ProtocolAuditor

TypeScript orchestrator for automated network protocol security audits. It drives a deterministic 5-stage pipeline and uses either Claude Code or Codex for stages 1 through 4 while Node handles parsing, checkpointing, concurrency, validation, and report generation.

## Why this exists

The original skill-driven workflow pushed too much code into a single analysis agent, especially in Stage 3. That breaks down on non-trivial protocol implementations.

This rewrite keeps the existing audit structure but fans work out at the right granularity:

- Stage 2: one agent per module
- Stage 3: one agent per entry point
- Stage 4: one agent per finding

The pipeline is resumable, bounded by a configurable concurrency limit, and no longer depends on Python.

## Prerequisites

- Node.js 18+
- `npm`
- One agent runtime:
  - Claude Code CLI installed and authenticated for `--agent claude-code`
  - Codex CLI installed and authenticated for `--agent codex`

## Installation

```bash
git clone https://github.com/COCOP1l0t/ProtocolAuditor.git
cd ProtocolAuditor
npm install
npm run build
```

## Usage

```bash
node dist/main.js --agent {claude-code|codex} --target PATH [options]
```

If you want a shell command instead of `node dist/main.js`, link the package first:

```bash
npm link
protocol-auditor --agent {claude-code|codex} --target PATH [options]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--agent {claude-code,codex}` | required | Which backend to use for stages 1-4 |
| `--target PATH` | required | Root directory of the project to audit |
| `--output-dir PATH` | `{target}/audit-output` | Output directory |
| `--max-parallel N` | `4` | Maximum concurrent agents |
| `--resume` | off | Reuse completed outputs and markers |
| `--threat-model TEXT` | network attacker with full packet control | Override the default threat model |
| `--scope TEXT` | empty | Additional stage-1 instructions |
| `--skip-stages LIST` | empty | Comma-separated stage numbers to skip |
| `--log-level LEVEL` | `INFO` | `DEBUG`, `INFO`, `WARNING`, `ERROR` |

### Examples

```bash
# Full audit with Claude Code
node dist/main.js --agent claude-code --target ~/projects/my-dhcp-server

# Full audit with Codex
node dist/main.js --agent codex --target ~/projects/my-dhcp-server

# Limit concurrency and write to a custom output dir
node dist/main.js --agent claude-code --target ~/projects/my-dns-impl \
  --max-parallel 2 \
  --output-dir /tmp/dns-audit

# Reuse existing analysis and regenerate only the final report
node dist/main.js --agent codex --target ~/projects/my-dns-impl \
  --skip-stages 1,2,3,4 \
  --output-dir /tmp/dns-audit
```

## Pipeline

```text
Stage 0  Setup          create output directories
Stage 1  Scope          one agent: orient, threat model, in-scope modules
Stage 2  Entry points   one agent per module
Stage 3  Analysis       one agent per entry point
Stage 4  Evaluation     one agent per finding
Stage 5  Report         deterministic Node report generator
```

Stages 2 through 4 are concurrency-limited and every stage can resume from written output plus marker files in `.markers/`.

## Output Layout

```text
{output_dir}/
├── .markers/
├── stage-1-scope.md
├── stage-2-details/
│   └── M-{N}.md
├── stage-3-details/
│   └── M-{N}-EP-{N}-F-{NN}.md
├── stage-4-details/
│   ├── _pending/
│   └── {ID}.md
└── report.md
```

## Repository Layout

```text
ProtocolAuditor/
├── reference/                Vendored language checklists used by Stage 3
├── src/                      TypeScript implementation
├── prompts/                  Stage prompt templates
├── README.md
└── DESIGN.md
```

## Verification

```bash
npm run check
npm test
```
