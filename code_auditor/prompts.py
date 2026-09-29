from __future__ import annotations

import re
from pathlib import Path

PROMPTS_DIR = Path(__file__).resolve().parent.parent / "prompts"

_PLACEHOLDER = re.compile(r"__[A-Z][A-Z0-9_]*?__")


def load_prompt(prompt_name: str, substitutions: dict[str, str]) -> str:
    text = (PROMPTS_DIR / prompt_name).read_text(encoding="utf-8")
    replacements = {f"__{key.upper()}__": value for key, value in substitutions.items()}
    # Validate the template, not inserted source code or finding metadata.
    # Values may legitimately contain identifiers such as __TAURI_INTERNALS__.
    missing = sorted(set(_PLACEHOLDER.findall(text)) - replacements.keys())
    if missing:
        raise ValueError(
            f"Unresolved placeholder(s) in {prompt_name}: {', '.join(missing)}"
        )
    # Substitute once so tokens and backslashes inside values stay literal,
    # even when they happen to match another template key.
    return _PLACEHOLDER.sub(lambda match: replacements[match.group()], text)
