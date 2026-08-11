from __future__ import annotations

import asyncio
import re
from pathlib import Path
from typing import Any, Callable, Coroutine, TypeVar

from .config import ValidationIssue

T = TypeVar("T")
R = TypeVar("R")


async def run_parallel_limited(
    items: list[T],
    concurrency: int,
    worker: Callable[[T, int], Coroutine[Any, Any, R]],
) -> list[tuple[str, R | None, Exception | None]]:
    """Run worker on each item with bounded concurrency. Returns (status, value, error) triples."""
    if not items:
        return []

    sem = asyncio.Semaphore(max(1, concurrency))
    results: list[tuple[str, R | None, Exception | None]] = [("pending", None, None)] * len(items)

    async def run_one(index: int, item: T) -> None:
        async with sem:
            try:
                value = await worker(item, index)
                results[index] = ("fulfilled", value, None)
            except Exception as exc:
                results[index] = ("rejected", None, exc)

    await asyncio.gather(*(run_one(i, item) for i, item in enumerate(items)))
    return results


def natural_sort_key(s: str) -> list[int | str]:
    """Sort key for natural ordering of strings containing numbers.

    Ensures e.g. 'AU-2' sorts before 'AU-10' instead of after 'AU-1'.
    """
    return [int(c) if c.isdigit() else c for c in re.split(r"(\d+)", s)]


def list_json_files(dir_path: str) -> list[str]:
    p = Path(dir_path)
    if not p.is_dir():
        return []
    return sorted((str(f) for f in p.iterdir() if f.is_file() and f.suffix == ".json"), key=natural_sort_key)


def list_matching_files(dir_path: str, pattern: re.Pattern[str]) -> list[str]:
    p = Path(dir_path)
    if not p.is_dir():
        return []
    return sorted((str(f) for f in p.iterdir() if f.is_file() and pattern.search(f.name)), key=natural_sort_key)


# Token-usage key variants emitted by the Claude SDK (snake_case) and the
# Codex app-server protocol (camelCase).
_USAGE_KEY_ALIASES = {
    "input_tokens": ("input_tokens", "inputTokens"),
    "output_tokens": ("output_tokens", "outputTokens"),
    "cache_creation_input_tokens": (
        "cache_creation_input_tokens",
        "cacheCreationInputTokens",
    ),
    "cache_read_input_tokens": (
        "cache_read_input_tokens",
        "cacheReadInputTokens",
        "cachedInputTokens",
    ),
}


def _usage_number(value: Any) -> float | None:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    return number if number >= 0 else None


def record_agent_usage(
    config: Any,
    usage: Any,
    cost_usd: float | None = None,
) -> None:
    """Accumulate one agent invocation's token/cost usage into the run."""
    stats = config.usage_stats
    stats["agent_calls"] = stats.get("agent_calls", 0) + 1
    if isinstance(usage, dict):
        for canonical, aliases in _USAGE_KEY_ALIASES.items():
            for alias in aliases:
                number = _usage_number(usage.get(alias))
                if number:
                    stats[canonical] = stats.get(canonical, 0) + number
                    break
    number = _usage_number(cost_usd)
    if number is not None:
        stats["cost_usd"] = stats.get("cost_usd", 0.0) + number


def format_validation_issues(issues: list[ValidationIssue]) -> str:
    if not issues:
        return "PASS: All checks passed."
    lines = [f"FAIL: {len(issues)} issue(s) found", ""]
    for i, issue in enumerate(issues, 1):
        lines.append(f"[Issue {i}] {issue.description}")
        lines.append(f"  Expected: {issue.expected}")
        lines.append(f"  Fix: {issue.fix}")
        lines.append("")
    return "\n".join(lines).rstrip()
