from __future__ import annotations

import pytest

from code_auditor.config import AuditConfig
from code_auditor.prompts import PROMPTS_DIR
from code_auditor.wiki import build_wiki_context


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


def test_stage3_wiki_context_does_not_parent_scope_or_task_sections() -> None:
    text = (PROMPTS_DIR / "stage3.md").read_text()

    scope_index = text.index("### Scope of Your Analysis")
    task_index = text.index("Your task: discover security bugs and vulnerabilities")
    wiki_index = text.index("## Wiki Knowledge Base")
    output_index = text.index("## Output")

    assert scope_index < task_index < wiki_index < output_index


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
