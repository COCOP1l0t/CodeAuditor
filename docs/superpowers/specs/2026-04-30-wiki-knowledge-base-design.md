# Read-Only Wiki Knowledge Base Support

## Problem Statement

CodeAuditor currently relies on live project research, git history, source review, and stage outputs. It cannot directly use a maintained LLM-oriented vulnerability wiki such as `/home/bea1e/QEMU-Vuln-Wiki`, even though that wiki contains durable audit knowledge: component risk maps, vulnerability class checklists, historical case studies, attack-surface notes, and reproduction guidance.

The goal is to add a read-only `--wiki` option that lets each audit stage search the most relevant wiki location for the knowledge it needs, without copying the whole wiki into every prompt and without mutating the knowledge base during an audit.

## Decisions

- Add `--wiki PATH` as an optional CLI argument.
- Store the resolved path in `AuditConfig.wiki_path: str | None`.
- Validate that `--wiki` points to an existing directory.
- Treat the wiki as read-only. The pipeline will never scaffold, edit, or update the wiki.
- Give backend agents filesystem access to the wiki path when it is outside the target or output directories.
- Inject concise stage-specific wiki guidance into prompts through a shared helper instead of hardcoding QEMU-specific paths in every stage runner.
- Support the current QEMU wiki shape as the recommended structure, while allowing partial wikis that only contain some of the expected files.

## Recommended Wiki Structure

```text
wiki/
├── index.md
├── overview.md
├── attack-surface.md
├── auditing-guide.md
├── exploit-patterns.md
├── reproduction-workflow.md
├── vulnerability-timeline.md
├── entities/
│   └── <component>.md
├── concepts/
│   └── <vulnerability-class>.md
└── sources/
    └── <cve-or-case-study>.md
```

Roles:

- `index.md`: catalog and first page to read when choosing relevant wiki pages.
- Root synthesis pages: project-wide audit thesis, attack surface, exploit patterns, reproduction process, and historical trends.
- `entities/`: component-specific audit maps, such as device models, protocol stacks, parsers, allocators, or storage engines.
- `concepts/`: vulnerability-class checklists, such as heap overflow, use-after-free, information leak, assertion failure, or denial of service.
- `sources/`: historical case studies and evidence cards, such as CVEs, advisories, or internal reproductions.

## Architecture

Add a new module, `code_auditor/wiki.py`, responsible for constructing stage-specific guidance text.

Proposed public API:

```python
def build_wiki_context(config: AuditConfig, stage: int) -> str:
    ...
```

If `config.wiki_path` is absent, it returns a short neutral string such as `No wiki knowledge base configured.` If present, it returns:

- the absolute wiki root path;
- the read-only rule;
- common lookup rules;
- stage-specific locations to search first;
- fallback behavior for missing optional files.

The helper should not read and inline full wiki contents. It should guide agents to search the right locations using their file tools. This preserves context budget and keeps the wiki as the source of truth.

## Stage-Specific Lookup Guidance

Stage 1: Security context research

- Start with `index.md` and `overview.md` if present.
- Search `vulnerability-timeline.md` and `sources/` for historical vulnerabilities, dates, affected components, root causes, and attacker profiles.
- Use root synthesis pages to supplement live project research, but keep source attribution clear in the Stage 1 research record.

Stage 2: Codebase decomposition

- Start with `index.md`, `attack-surface.md`, `auditing-guide.md`, and `entities/`.
- Use entity pages to identify components that historically produce impactful vulnerabilities.
- Use concept pages only when they help explain why an area is selected for analysis.
- Reflect relevant wiki knowledge in `triage.json` rationales and AU `focus` fields.

Stage 3: Vulnerability analysis

- Start from the AU files and search `entities/` for matching components or subsystem names.
- Search `concepts/` for vulnerability classes suggested by the code path.
- Search `exploit-patterns.md` and matching `sources/` pages for historical bug shapes.
- Use wiki pages as audit heuristics, not as proof that the current target is vulnerable.

Stage 4: Vulnerability evaluation

- Search `concepts/` and relevant `sources/` pages to calibrate false-positive checks, impact, and historical severity.
- Use `vulnerability-timeline.md` for broad historical comparison when useful.
- Do not confirm a vulnerability solely because a wiki page describes a similar historical issue; the source data-flow trace remains authoritative.

Stage 5: PoC reproduction

- Start with `reproduction-workflow.md`.
- Search matching entity, concept, and source pages for realistic trigger models, environment setup, expected evidence, and reproduction pitfalls.
- Use the wiki to choose the lowest reproduction level that preserves the vulnerable data flow.

Stage 6: Disclosure preparation

- Search relevant entity, concept, source, and reproduction pages for clear framing and maintainer-facing terminology.
- Use the wiki to improve report clarity, but keep disclosure claims grounded in Stage 5 evidence and the target source.
- Do not include internal wiki links or paths in disclosure artifacts unless they are explicitly useful and appropriate for the recipient.

## Prompt Integration

Each stage prompt gets a new `## Wiki Knowledge Base` section populated by a `__WIKI_CONTEXT__` placeholder. Stages without a configured wiki receive the neutral no-wiki message.

Stage runners call `build_wiki_context(config, stage=N)` and pass it to `load_prompt()`.

This keeps prompt behavior explicit and testable without changing the agent contract or output schemas.

## Backend Filesystem Access

Update agent additional-directory handling so the configured wiki path is included alongside the output directory when:

- the path exists;
- it is not the current working directory;
- it is not already included.

This matters for wikis outside the target tree, such as `/home/bea1e/QEMU-Vuln-Wiki`.

## CLI And Config

CLI:

```bash
code-auditor --target /path/to/project --wiki /path/to/wiki
```

Validation:

- Resolve the path with `os.path.realpath`.
- Reject missing paths.
- Reject non-directories.
- Do not create the path.

Config:

```python
@dataclass
class AuditConfig:
    ...
    wiki_path: str | None = None
```

## Testing

Add focused tests for:

- CLI accepts `--wiki`.
- `main()` resolves and passes `wiki_path` into `AuditConfig`.
- invalid wiki paths fail before `run_audit()`.
- `build_wiki_context()` returns a neutral message when no wiki is configured.
- `build_wiki_context()` returns stage-specific lookup guidance when a wiki is configured.
- `_additional_directories()` includes the wiki path when it exists and is outside the agent cwd.

No tests should make real agent calls.

## Documentation

Update `README.md` common options with `--wiki`.

Add a short "Wiki Knowledge Base" section explaining:

- the option is read-only;
- the recommended directory structure;
- each stage searches the wiki for stage-specific knowledge;
- partial wikis are allowed, but `index.md` is recommended.

Update `CLAUDE.md` quick reference with the new option.

## Out Of Scope

- Creating or scaffolding a wiki.
- Updating wiki pages during or after an audit.
- Building a vector index or embedding search.
- Injecting full wiki page contents into prompts by default.
- Changing stage output schemas or validators for wiki citations.
