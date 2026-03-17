# ProtocolAuditor Design

## Summary

ProtocolAuditor is now a Node/TypeScript application. The runtime split is:

- TypeScript orchestrator for CLI parsing, checkpointing, concurrency, validation, parsing, and report generation
- Claude Code CLI for Claude-backed analysis stages
- Codex TypeScript SDK for Codex-backed analysis stages

The project keeps the original 5-stage audit pipeline and file formats, but removes the Python package entirely.

## Core Decisions

- Stage 3 remains one agent per entry point
- Stage 4 remains one agent per finding
- Resume state is still file- and marker-based
- Validation and report generation are deterministic Node modules
- Prompt templates remain markdown assets outside `dist/`
- Language checklists are vendored locally under `reference/`

## Layout

```text
reference/
├── checklist-c-cpp.md
├── checklist-go.md
├── checklist-managed.md
└── checklist-rust.md

src/
├── main.ts
├── orchestrator.ts
├── config.ts
├── checkpoint.ts
├── logger.ts
├── prompts.ts
├── utils.ts
├── agents/
│   └── index.ts
├── parsing/
│   ├── stage1.ts
│   └── stage2.ts
├── validation/
│   ├── common.ts
│   ├── stage1.ts
│   ├── stage2.ts
│   ├── stage3.ts
│   └── stage4.ts
├── report/
│   ├── generate.ts
│   └── helpers.ts
├── stages/
│   ├── stage0.ts
│   ├── stage1.ts
│   ├── stage2.ts
│   ├── stage3.ts
│   ├── stage4.ts
│   └── stage5.ts
└── test/
    └── parsers-and-report.test.ts
```

## Backend Adapters

### Claude Code

The Claude backend shells out to `claude --print` with write-capable tools enabled. The agent receives the prompt, edits files directly in the target workspace, and returns a final text response that the orchestrator only uses for logging and repair loops.

### Codex

The Codex backend uses `@openai/codex-sdk` directly. Each stage starts a fresh thread with:

- `approvalPolicy: "never"`
- `sandboxMode: "danger-full-access"`
- `skipGitRepoCheck: true`
- additional writable directories for output and checklist assets when needed

## Deterministic Components

The TypeScript implementation owns:

- Stage 1 module parsing
- Stage 2 entry-point parsing
- Stage 1 through 4 validation
- Stage 4 ID assignment and file finalization
- Stage 5 report generation

These pieces are intentionally non-agentic so the fan-out stages can be resumed and verified without reparsing model prose heuristically.
