from __future__ import annotations

import logging
import asyncio
from types import SimpleNamespace

from code_auditor.utils import collect_parallel_results, run_parallel_limited


def test_collect_parallel_results_preserves_truthy_values_and_records_errors(caplog) -> None:
    config = SimpleNamespace(task_errors=[])
    items = ["first.json", "second.json", "third.json", "fourth.json"]
    results = [
        ("fulfilled", "first", None),
        ("rejected", None, ValueError("broken")),
        ("fulfilled", "", None),
        ("fulfilled", "fourth", None),
        ("fulfilled", "ignored", None),
    ]

    with caplog.at_level(logging.ERROR):
        collected = collect_parallel_results(
            results,
            items,
            stage="stage5",
            config=config,
            logger=logging.getLogger("test.parallel"),
            item_id=lambda item: item.removesuffix(".json"),
            item_log=lambda item: item,
        )

    assert collected == ["first", "fourth"]
    assert len(config.task_errors) == 1
    assert config.task_errors == ["stage5:second: broken"]
    assert "Stage 5: second.json failed: broken" in caplog.text


def test_collect_parallel_results_handles_empty_results() -> None:
    config = SimpleNamespace(task_errors=[])

    assert collect_parallel_results(
        [],
        [],
        stage="stage3",
        config=config,
        logger=logging.getLogger("test.parallel.empty"),
        item_id=str,
    ) == []
    assert config.task_errors == []


def test_run_parallel_limited_reports_each_completion() -> None:
    completed: list[tuple[int, str]] = []

    async def worker(item: str, index: int) -> str:
        if item == "bad":
            raise ValueError("broken")
        return item.upper()

    results = asyncio.run(
        run_parallel_limited(
            ["a", "bad", "c"],
            2,
            worker,
            on_complete=lambda index, item: completed.append((index, item)),
        )
    )

    assert [status for status, _value, _error in results] == [
        "fulfilled",
        "rejected",
        "fulfilled",
    ]
    assert sorted(completed) == [(0, "a"), (1, "bad"), (2, "c")]
