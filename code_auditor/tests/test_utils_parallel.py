from __future__ import annotations

import logging
from types import SimpleNamespace

from code_auditor.utils import collect_parallel_results


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
