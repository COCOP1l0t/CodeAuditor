from pathlib import Path

import pytest

from code_auditor import prompts


def test_prompt_templates_are_bundled_with_the_package() -> None:
    assert prompts.PROMPTS_DIR == Path(prompts.__file__).resolve().parent / "prompts"
    assert (prompts.PROMPTS_DIR / "stage1.md").is_file()
    assert (prompts.PROMPTS_DIR / "stage6.md").is_file()


@pytest.mark.parametrize(
    "value",
    ["window.__TAURI_INTERNALS__.invoke", "__NEXT__", r"C:\source\1\file", ""],
)
def test_prompt_values_are_literal(tmp_path: Path, monkeypatch, value: str) -> None:
    (tmp_path / "example.md").write_text("__VALUE__\n__NEXT__\n__VALUE__")
    monkeypatch.setattr(prompts, "PROMPTS_DIR", tmp_path)

    assert prompts.load_prompt(
        "example.md", {"value": value, "next": "replacement"}
    ) == f"{value}\nreplacement\n{value}"


def test_prompt_rejects_missing_template_keys(tmp_path: Path, monkeypatch) -> None:
    (tmp_path / "example.md").write_text("__VALUE__ __MISSING__ __MISSING__")
    monkeypatch.setattr(prompts, "PROMPTS_DIR", tmp_path)

    with pytest.raises(ValueError) as exc:
        prompts.load_prompt("example.md", {"value": "__TAURI_INTERNALS__"})

    assert str(exc.value) == "Unresolved placeholder(s) in example.md: __MISSING__"


def test_prompt_replaces_adjacent_tokens_and_preserves_suffixes(
    tmp_path: Path, monkeypatch
) -> None:
    (tmp_path / "example.md").write_text("__FIRST____SECOND__ __POC_DIR___fp")
    monkeypatch.setattr(prompts, "PROMPTS_DIR", tmp_path)

    assert prompts.load_prompt(
        "example.md", {"first": "one", "second": "two", "poc_dir": "/tmp/poc"}
    ) == "onetwo /tmp/poc_fp"
