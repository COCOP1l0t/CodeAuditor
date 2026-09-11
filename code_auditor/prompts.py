from __future__ import annotations

import re
from pathlib import Path

PROMPTS_DIR = Path(__file__).resolve().parent.parent / "prompts"

_LEFTOVER_PLACEHOLDER = re.compile(r"__[A-Z][A-Z0-9_]*__")


def load_prompt(prompt_name: str, substitutions: dict[str, str]) -> str:
    text = (PROMPTS_DIR / prompt_name).read_text(encoding="utf-8")
    for key, value in substitutions.items():
        text = text.replace(f"__{key.upper()}__", value)
    # A renamed or newly added template key must not silently ship a literal
    # ``__KEY__`` token to the agent.
    leftover = sorted(set(_LEFTOVER_PLACEHOLDER.findall(text)))
    if leftover:
        raise ValueError(
            f"Unresolved placeholder(s) in {prompt_name}: {', '.join(leftover)}"
        )
    return text
