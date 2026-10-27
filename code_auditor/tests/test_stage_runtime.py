from __future__ import annotations

from pathlib import Path

import pytest

from code_auditor.config import AuditConfig
from code_auditor.layout import stage1_paths, stage4_paths, stage_state_path
from code_auditor.stage_runtime import repair_until_valid, stage_span
from code_auditor.stage_state import StageStateStore, read_stage_state


def test_layout_paths_are_canonical(tmp_path: Path) -> None:
    assert stage1_paths(str(tmp_path))["record"] == str(
        tmp_path / "stage1-security-context" / "stage-1-security-context.json"
    )
    assert stage4_paths(str(tmp_path))["pending"] == str(
        tmp_path / "stage4-vulnerabilities" / "_pending"
    )
    assert stage_state_path(str(tmp_path)) == str(tmp_path / ".stage-state.json")


async def test_repair_until_valid_stops_after_success() -> None:
    valid = False
    repair_calls: list[str] = []

    def validator():
        return [] if valid else [object()]

    async def repair(prompt: str) -> None:
        nonlocal valid
        repair_calls.append(prompt)
        valid = True

    issues = await repair_until_valid(
        validator=validator,
        repair=repair,
        repair_prompt=lambda current: f"repair {len(current)}",
        max_attempts=2,
    )

    assert issues == []
    assert repair_calls == ["repair 1"]


async def test_stage_span_persists_done_state_and_progress(tmp_path: Path) -> None:
    class Reporter:
        def __init__(self) -> None:
            self.events: list[tuple] = []

        def begin_stage(self, stage: int, description: str) -> None:
            self.events.append(("begin", stage, description))

        def stage_progress(self, stage: int, **values) -> None:
            self.events.append(("progress", stage, values))

        def end_stage(self, stage: int) -> None:
            self.events.append(("end", stage))

    reporter = Reporter()
    store = StageStateStore(str(tmp_path))
    config = AuditConfig(target=str(tmp_path), output_dir=str(tmp_path))

    async with stage_span(
        config, reporter, store, 3, "Testing stage lifecycle"
    ) as progress:
        progress.update(items_done=2, items_total=4, detail="half")

    persisted = read_stage_state(str(tmp_path))
    assert persisted[3]["status"] == "done"
    assert persisted[3]["items_done"] == 2
    assert persisted[3]["items_total"] == 4
    assert reporter.events == [
        ("begin", 3, "Testing stage lifecycle"),
        ("progress", 3, {"items_done": 2, "items_total": 4, "detail": "half"}),
        ("end", 3),
    ]
