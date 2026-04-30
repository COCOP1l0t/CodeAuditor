# Wiki Knowledge Base Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a read-only `--wiki` option that lets every audit stage search an existing LLM wiki knowledge base in stage-appropriate locations.

**Architecture:** Store the resolved wiki directory on `AuditConfig`, expose it to backend agents as an additional readable directory, and inject stage-specific wiki lookup guidance into prompt templates through a small `code_auditor/wiki.py` helper. The helper guides agents to search the wiki instead of inlining full page contents, preserving context budget and keeping the wiki read-only.

**Tech Stack:** Python 3.12, argparse, dataclasses, pytest, existing prompt substitution via `code_auditor/prompts.py`.

---

## File Structure

- Modify `code_auditor/config.py`: add `wiki_path` to `AuditConfig`.
- Modify `code_auditor/__main__.py`: add `--wiki`, validate it as an existing directory, pass the resolved path to `AuditConfig`.
- Create `code_auditor/wiki.py`: build neutral or stage-specific wiki guidance text.
- Modify `code_auditor/agent.py`: include `config.wiki_path` in additional readable directories for backend agents.
- Modify `code_auditor/stages/stage1.py` through `code_auditor/stages/stage6.py`: pass `build_wiki_context(config, stage=N)` into prompt substitutions.
- Modify `prompts/stage1.md` through `prompts/stage6.md`: add a `## Wiki Knowledge Base` section with `__WIKI_CONTEXT__`.
- Modify `code_auditor/tests/test_backend_selection.py`: cover CLI/config and additional-directory behavior.
- Create `code_auditor/tests/test_wiki_context.py`: cover the wiki helper and prompt template tokens.
- Modify `README.md`: document `--wiki` and the recommended wiki layout.
- Modify `CLAUDE.md`: add the quick-reference option.

---

### Task 1: CLI And Config

**Files:**
- Modify: `code_auditor/config.py`
- Modify: `code_auditor/__main__.py`
- Modify: `code_auditor/tests/test_backend_selection.py`

- [ ] **Step 1: Write failing CLI/config tests**

Add these tests to `code_auditor/tests/test_backend_selection.py`. Keep the existing tests and imports. Ensure `sys`, `pytest`, `main_module`, and `AuditConfig` are imported, because these tests use them.

```python
def test_cli_accepts_wiki_path() -> None:
    args = _build_parser().parse_args([
        "--target",
        ".",
        "--wiki",
        "/tmp/wiki",
    ])

    assert args.wiki == "/tmp/wiki"


def test_main_maps_wiki_path_to_config(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:  # type: ignore[no-untyped-def]
    captured: dict[str, AuditConfig] = {}
    target = tmp_path / "target"
    wiki = tmp_path / "wiki"
    target.mkdir()
    wiki.mkdir()

    async def fake_run_audit(config: AuditConfig) -> None:
        captured["config"] = config

    monkeypatch.setattr(main_module, "run_audit", fake_run_audit)
    monkeypatch.setattr(sys, "argv", [
        "code-auditor",
        "--target",
        str(target),
        "--wiki",
        str(wiki),
    ])

    main_module.main()

    assert captured["config"].wiki_path == str(wiki.resolve())


def test_main_rejects_missing_wiki_path(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    target = tmp_path / "target"
    missing_wiki = tmp_path / "missing-wiki"
    target.mkdir()

    monkeypatch.setattr(sys, "argv", [
        "code-auditor",
        "--target",
        str(target),
        "--wiki",
        str(missing_wiki),
    ])

    with pytest.raises(SystemExit) as exc:
        main_module.main()

    assert exc.value.code == 1
    assert f"Error: Wiki directory not found: {missing_wiki.resolve()}" in capsys.readouterr().err


def test_main_rejects_wiki_file_path(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    target = tmp_path / "target"
    wiki_file = tmp_path / "wiki.md"
    target.mkdir()
    wiki_file.write_text("# Not a directory\n")

    monkeypatch.setattr(sys, "argv", [
        "code-auditor",
        "--target",
        str(target),
        "--wiki",
        str(wiki_file),
    ])

    with pytest.raises(SystemExit) as exc:
        main_module.main()

    assert exc.value.code == 1
    assert f"Error: Wiki path is not a directory: {wiki_file.resolve()}" in capsys.readouterr().err
```

- [ ] **Step 2: Run tests to verify they fail**

Run:

```bash
pytest code_auditor/tests/test_backend_selection.py::test_cli_accepts_wiki_path code_auditor/tests/test_backend_selection.py::test_main_maps_wiki_path_to_config code_auditor/tests/test_backend_selection.py::test_main_rejects_missing_wiki_path code_auditor/tests/test_backend_selection.py::test_main_rejects_wiki_file_path -v
```

Expected: at least one failure caused by missing `--wiki` support or missing `AuditConfig.wiki_path`.

- [ ] **Step 3: Add config field**

In `code_auditor/config.py`, add this field to `AuditConfig` after `output_dir`:

```python
    wiki_path: str | None = None
```

- [ ] **Step 4: Add CLI parsing and validation**

In `code_auditor/__main__.py`, add this parser argument after `--output-dir`:

```python
    parser.add_argument("--wiki", help="Read-only LLM wiki knowledge base directory")
```

Add this helper near `_build_parser()`:

```python
def _resolve_wiki_path(path: str | None) -> str | None:
    if not path:
        return None

    resolved = os.path.realpath(path)
    if not os.path.exists(resolved):
        print(f"Error: Wiki directory not found: {resolved}", file=sys.stderr)
        sys.exit(1)
    if not os.path.isdir(resolved):
        print(f"Error: Wiki path is not a directory: {resolved}", file=sys.stderr)
        sys.exit(1)
    return resolved
```

In `main()`, resolve the wiki after `output_dir`:

```python
    wiki_path = _resolve_wiki_path(args.wiki)
```

Pass it to `AuditConfig`:

```python
        wiki_path=wiki_path,
```

- [ ] **Step 5: Run tests to verify they pass**

Run:

```bash
pytest code_auditor/tests/test_backend_selection.py::test_cli_accepts_wiki_path code_auditor/tests/test_backend_selection.py::test_main_maps_wiki_path_to_config code_auditor/tests/test_backend_selection.py::test_main_rejects_missing_wiki_path code_auditor/tests/test_backend_selection.py::test_main_rejects_wiki_file_path -v
```

Expected: all four tests pass.

- [ ] **Step 6: Commit**

```bash
git add code_auditor/config.py code_auditor/__main__.py code_auditor/tests/test_backend_selection.py
git commit -m "Add read-only wiki CLI option"
```

---

### Task 2: Wiki Context Helper

**Files:**
- Create: `code_auditor/wiki.py`
- Create: `code_auditor/tests/test_wiki_context.py`

- [ ] **Step 1: Write failing wiki helper tests**

Create `code_auditor/tests/test_wiki_context.py` with:

```python
from __future__ import annotations

from code_auditor.config import AuditConfig
from code_auditor.wiki import build_wiki_context


def test_build_wiki_context_returns_neutral_message_without_wiki() -> None:
    config = AuditConfig(target="/tmp/project", output_dir="/tmp/output")

    assert build_wiki_context(config, stage=3) == "No wiki knowledge base configured."


def test_build_wiki_context_stage2_points_to_decomposition_locations(tmp_path) -> None:  # type: ignore[no-untyped-def]
    wiki = tmp_path / "wiki"
    wiki.mkdir()
    config = AuditConfig(target="/tmp/project", output_dir="/tmp/output", wiki_path=str(wiki))

    context = build_wiki_context(config, stage=2)

    assert f"Wiki root: `{wiki}`" in context
    assert "read-only" in context
    assert "index.md" in context
    assert "attack-surface.md" in context
    assert "auditing-guide.md" in context
    assert "entities/" in context
    assert "triage.json" in context


def test_build_wiki_context_stage5_points_to_reproduction_locations(tmp_path) -> None:  # type: ignore[no-untyped-def]
    wiki = tmp_path / "wiki"
    wiki.mkdir()
    config = AuditConfig(target="/tmp/project", output_dir="/tmp/output", wiki_path=str(wiki))

    context = build_wiki_context(config, stage=5)

    assert "reproduction-workflow.md" in context
    assert "expected evidence" in context
    assert "entity" in context
    assert "source" in context


def test_build_wiki_context_unknown_stage_uses_generic_guidance(tmp_path) -> None:  # type: ignore[no-untyped-def]
    wiki = tmp_path / "wiki"
    wiki.mkdir()
    config = AuditConfig(target="/tmp/project", output_dir="/tmp/output", wiki_path=str(wiki))

    context = build_wiki_context(config, stage=99)

    assert "index.md" in context
    assert "Use the wiki only as supporting audit knowledge." in context
```

- [ ] **Step 2: Run tests to verify they fail**

Run:

```bash
pytest code_auditor/tests/test_wiki_context.py -v
```

Expected: import failure for `code_auditor.wiki`.

- [ ] **Step 3: Implement the wiki helper**

Create `code_auditor/wiki.py`:

```python
from __future__ import annotations

from .config import AuditConfig

NO_WIKI_CONTEXT = "No wiki knowledge base configured."

_GENERIC_GUIDANCE = (
    "Use the wiki only as supporting audit knowledge. Start with `index.md` if it exists, "
    "then search root synthesis pages, `entities/`, `concepts/`, and `sources/` for pages "
    "matching the current component, vulnerability class, or historical pattern."
)

_STAGE_GUIDANCE: dict[int, str] = {
    1: (
        "Stage 1 lookup: start with `index.md` and `overview.md` if present. Search "
        "`vulnerability-timeline.md` and `sources/` for historical vulnerabilities, dates, "
        "affected components, root causes, impacts, and attacker profiles. Use root synthesis "
        "pages to supplement live research, and keep source attribution clear in the research record."
    ),
    2: (
        "Stage 2 lookup: start with `index.md`, `attack-surface.md`, `auditing-guide.md`, "
        "and `entities/`. Use entity pages to identify components that historically produce "
        "impactful vulnerabilities. Use concept pages when they help explain why an area is "
        "selected. Reflect relevant wiki knowledge in `triage.json` rationales and AU `focus` fields."
    ),
    3: (
        "Stage 3 lookup: start from the AU files, then search `entities/` for matching components "
        "or subsystem names. Search `concepts/` for vulnerability classes suggested by the code path. "
        "Search `exploit-patterns.md` and matching `sources/` pages for historical bug shapes. "
        "Use wiki pages as audit heuristics, not proof that this target is vulnerable."
    ),
    4: (
        "Stage 4 lookup: search `concepts/` and relevant `sources/` pages to calibrate "
        "false-positive checks, impact, and historical severity. Use `vulnerability-timeline.md` "
        "for broad historical comparison when useful. Do not confirm a vulnerability solely because "
        "a wiki page describes a similar historical issue; the source data-flow trace is authoritative."
    ),
    5: (
        "Stage 5 lookup: start with `reproduction-workflow.md`. Search matching entity, concept, "
        "and source pages for realistic trigger models, environment setup, expected evidence, and "
        "reproduction pitfalls. Use the wiki to choose the lowest reproduction level that preserves "
        "the vulnerable data flow."
    ),
    6: (
        "Stage 6 lookup: search relevant entity, concept, source, and reproduction pages for clear "
        "framing and maintainer-facing terminology. Use the wiki to improve report clarity, but keep "
        "disclosure claims grounded in Stage 5 evidence and the target source. Do not include internal "
        "wiki links or paths in disclosure artifacts unless they are explicitly useful for the recipient."
    ),
}


def build_wiki_context(config: AuditConfig, stage: int) -> str:
    if not config.wiki_path:
        return NO_WIKI_CONTEXT

    stage_guidance = _STAGE_GUIDANCE.get(stage, _GENERIC_GUIDANCE)
    return "\n".join([
        f"Wiki root: `{config.wiki_path}`",
        "The wiki is read-only. Do not create, edit, move, or delete files in it.",
        "If a referenced wiki file or directory is absent, skip it and continue with the available pages.",
        "Prefer `index.md` for navigation when it exists.",
        stage_guidance,
    ])
```

- [ ] **Step 4: Run helper tests again**

Run:

```bash
pytest code_auditor/tests/test_wiki_context.py -v
```

Expected: all helper tests pass.

- [ ] **Step 5: Commit helper and helper tests**

Commit the helper and its tests:

```bash
git add code_auditor/wiki.py code_auditor/tests/test_wiki_context.py
git commit -m "Add wiki context guidance helper"
```

---

### Task 3: Backend Additional Directory Access

**Files:**
- Modify: `code_auditor/agent.py`
- Modify: `code_auditor/tests/test_backend_selection.py`

- [ ] **Step 1: Write failing additional-directory tests**

Add these tests to `code_auditor/tests/test_backend_selection.py`:

```python
def test_additional_directories_includes_existing_wiki_path(tmp_path) -> None:  # type: ignore[no-untyped-def]
    target = tmp_path / "target"
    output = tmp_path / "output"
    wiki = tmp_path / "wiki"
    target.mkdir()
    output.mkdir()
    wiki.mkdir()
    config = AuditConfig(
        target=str(target),
        output_dir=str(output),
        wiki_path=str(wiki),
    )

    assert agent._additional_directories(config, str(target)) == [
        str(output.resolve()),
        str(wiki.resolve()),
    ]


def test_additional_directories_skips_wiki_when_it_is_cwd(tmp_path) -> None:  # type: ignore[no-untyped-def]
    target = tmp_path / "target"
    output = tmp_path / "output"
    target.mkdir()
    output.mkdir()
    config = AuditConfig(
        target=str(target),
        output_dir=str(output),
        wiki_path=str(target),
    )

    assert agent._additional_directories(config, str(target)) == [str(output.resolve())]
```

- [ ] **Step 2: Run tests to verify they fail**

Run:

```bash
pytest code_auditor/tests/test_backend_selection.py::test_additional_directories_includes_existing_wiki_path code_auditor/tests/test_backend_selection.py::test_additional_directories_skips_wiki_when_it_is_cwd -v
```

Expected: first test fails because `_additional_directories()` only includes `output_dir`.

- [ ] **Step 3: Update additional-directory logic**

In `code_auditor/agent.py`, replace the loop in `_additional_directories()` with:

```python
    for candidate in [config.output_dir, config.wiki_path]:
        if not candidate:
            continue
        resolved = os.path.realpath(candidate)
        if resolved != resolved_cwd and os.path.isdir(resolved) and resolved not in dirs:
            dirs.append(resolved)
```

- [ ] **Step 4: Run tests to verify they pass**

Run:

```bash
pytest code_auditor/tests/test_backend_selection.py::test_additional_directories_includes_existing_wiki_path code_auditor/tests/test_backend_selection.py::test_additional_directories_skips_wiki_when_it_is_cwd -v
```

Expected: both tests pass.

- [ ] **Step 5: Commit**

```bash
git add code_auditor/agent.py code_auditor/tests/test_backend_selection.py
git commit -m "Expose wiki directory to audit agents"
```

---

### Task 4: Prompt Injection Across Stages

**Files:**
- Modify: `code_auditor/stages/stage1.py`
- Modify: `code_auditor/stages/stage2.py`
- Modify: `code_auditor/stages/stage3.py`
- Modify: `code_auditor/stages/stage4.py`
- Modify: `code_auditor/stages/stage5.py`
- Modify: `code_auditor/stages/stage6.py`
- Modify: `prompts/stage1.md`
- Modify: `prompts/stage2.md`
- Modify: `prompts/stage3.md`
- Modify: `prompts/stage4.md`
- Modify: `prompts/stage5.md`
- Modify: `prompts/stage6.md`
- Modify or create: `code_auditor/tests/test_wiki_context.py`

- [ ] **Step 1: Write failing prompt-template tests**

Add these imports to `code_auditor/tests/test_wiki_context.py` if they are not already present:

```python
import pytest

from code_auditor.prompts import PROMPTS_DIR
```

Add this test to the same file:

```python
@pytest.mark.parametrize("prompt_name", [
    "stage1.md",
    "stage2.md",
    "stage3.md",
    "stage4.md",
    "stage5.md",
    "stage6.md",
])
def test_stage_prompt_templates_have_wiki_context_token(prompt_name: str) -> None:
    text = (PROMPTS_DIR / prompt_name).read_text()

    assert "## Wiki Knowledge Base" in text
    assert "__WIKI_CONTEXT__" in text
```

- [ ] **Step 2: Run prompt-template tests to verify they fail**

Run:

```bash
pytest code_auditor/tests/test_wiki_context.py::test_stage_prompt_templates_have_wiki_context_token -v
```

Expected: the test fails for stage prompt templates that do not yet include the wiki section.

- [ ] **Step 3: Add wiki context imports to stage runners**

In each of `code_auditor/stages/stage1.py` through `code_auditor/stages/stage6.py`, add:

```python
from ..wiki import build_wiki_context
```

- [ ] **Step 4: Add prompt substitutions**

Add `"wiki_context": build_wiki_context(config, stage=N),` to each `load_prompt()` substitutions dictionary, using the matching stage number.

For Stage 1:

```python
        "wiki_context": build_wiki_context(config, stage=1),
```

For Stage 2:

```python
        "wiki_context": build_wiki_context(config, stage=2),
```

For Stage 3:

```python
        "wiki_context": build_wiki_context(config, stage=3),
```

For Stage 4:

```python
        "wiki_context": build_wiki_context(config, stage=4),
```

For Stage 5:

```python
        "wiki_context": build_wiki_context(config, stage=5),
```

For Stage 6:

```python
        "wiki_context": build_wiki_context(config, stage=6),
```

- [ ] **Step 5: Add wiki sections to prompt templates**

In each prompt template, insert this section after the existing input or user-instructions block and before the workflow-specific instructions:

```markdown
## Wiki Knowledge Base

__WIKI_CONTEXT__
```

For `prompts/stage1.md`, insert it after the `## User Instructions` block.

For `prompts/stage2.md`, insert it after the `## User Instructions` block.

For `prompts/stage3.md`, insert it after the assignment paragraphs and before `### Scope of Your Analysis`.

For `prompts/stage4.md`, insert it after the input list and before `## Workflow`.

For `prompts/stage5.md`, insert it after the `## Input` section and before the red-flags table.

For `prompts/stage6.md`, insert it after the `## Input` section and before the red-flags table.

- [ ] **Step 6: Run wiki tests**

Run:

```bash
pytest code_auditor/tests/test_wiki_context.py -v
```

Expected: all wiki-context tests pass.

- [ ] **Step 7: Commit**

```bash
git add code_auditor/wiki.py code_auditor/tests/test_wiki_context.py code_auditor/stages/stage1.py code_auditor/stages/stage2.py code_auditor/stages/stage3.py code_auditor/stages/stage4.py code_auditor/stages/stage5.py code_auditor/stages/stage6.py prompts/stage1.md prompts/stage2.md prompts/stage3.md prompts/stage4.md prompts/stage5.md prompts/stage6.md
git commit -m "Inject wiki guidance into audit stages"
```

---

### Task 5: Documentation

**Files:**
- Modify: `README.md`
- Modify: `CLAUDE.md`

- [ ] **Step 1: Update README common options**

In `README.md`, add this row to the common options table:

```markdown
| `--wiki` | Read-only LLM wiki knowledge base directory. Each stage searches stage-appropriate wiki pages for audit guidance. |
```

- [ ] **Step 2: Add README wiki section**

Add this section after the common options table and before the resume/checkpoint paragraph:

````markdown
### Wiki knowledge base

`--wiki /path/to/wiki` lets CodeAuditor use an existing read-only LLM wiki knowledge base during the audit. Agents may read and search the wiki, but they do not create, edit, or update wiki files.

Recommended structure:

```text
wiki/
|-- index.md
|-- overview.md
|-- attack-surface.md
|-- auditing-guide.md
|-- exploit-patterns.md
|-- reproduction-workflow.md
|-- vulnerability-timeline.md
|-- entities/
|   `-- <component>.md
|-- concepts/
|   `-- <vulnerability-class>.md
`-- sources/
    `-- <cve-or-case-study>.md
```

`index.md` is recommended as the navigation entry point. Partial wikis are supported; stages skip absent files and use the pages that exist.
````

- [ ] **Step 3: Update README example**

Update the example command to include `--wiki`:

```bash
code-auditor \
  --target ~/projects/libfoo \
  --output-dir ~/audits/libfoo \
  --wiki ~/knowledge/libfoo-wiki \
  --max-parallel 4 \
  --log-level DEBUG
```

- [ ] **Step 4: Update CLAUDE quick reference**

In `CLAUDE.md`, add this option to the quick reference list:

```markdown
#   --wiki            Read-only LLM wiki knowledge base directory
```

- [ ] **Step 5: Run documentation checks**

Run:

```bash
rg -n -- "--wiki|Wiki knowledge base|read-only LLM wiki" README.md CLAUDE.md
```

Expected: output includes the README option row, README section heading/content, example command, and CLAUDE quick-reference option.

- [ ] **Step 6: Commit**

```bash
git add README.md CLAUDE.md
git commit -m "Document wiki knowledge base support"
```

---

### Task 6: Full Verification

**Files:**
- No new files

- [ ] **Step 1: Run focused tests**

Run:

```bash
pytest code_auditor/tests/test_backend_selection.py code_auditor/tests/test_wiki_context.py -v
```

Expected: all tests pass.

- [ ] **Step 2: Run full test suite**

Run:

```bash
pytest -v
```

Expected: all tests pass.

- [ ] **Step 3: Run whitespace check**

Run:

```bash
git diff --check
```

Expected: no output.

- [ ] **Step 4: Inspect changed files**

Run:

```bash
git status --short
```

Expected: only intended files are modified or untracked before the final commit. Existing unrelated user edits may still appear; do not revert them.

- [ ] **Step 5: Final commit if verification produced cleanup edits**

If verification required cleanup changes, commit only the files changed for wiki support:

```bash
git add code_auditor/config.py code_auditor/__main__.py code_auditor/wiki.py code_auditor/agent.py code_auditor/stages/stage1.py code_auditor/stages/stage2.py code_auditor/stages/stage3.py code_auditor/stages/stage4.py code_auditor/stages/stage5.py code_auditor/stages/stage6.py prompts/stage1.md prompts/stage2.md prompts/stage3.md prompts/stage4.md prompts/stage5.md prompts/stage6.md code_auditor/tests/test_backend_selection.py code_auditor/tests/test_wiki_context.py README.md CLAUDE.md
git commit -m "Finalize wiki knowledge base support"
```
