"""Shared stage lifecycle, validation, repair, and checkpoint helpers."""

from __future__ import annotations

import asyncio
import contextlib
import os
from collections.abc import AsyncIterator, Awaitable, Callable
from dataclasses import dataclass

from .checkpoint import CheckpointManager
from .config import AuditConfig, ValidationIssue
from .logger import get_logger
from .stage_state import StageStateStore

logger = get_logger("stage_runtime")

Repair = Callable[[str], Awaitable[object]]
Validator = Callable[[], list[ValidationIssue]]
RepairPrompt = Callable[[list[ValidationIssue]], str]


async def repair_until_valid(
    *,
    validator: Validator,
    repair: Repair,
    repair_prompt: RepairPrompt,
    max_attempts: int = 1,
    timeout_seconds: float | None = None,
) -> list[ValidationIssue]:
    """Validate once, then run bounded repair attempts until output is valid."""
    issues = validator()
    for attempt in range(max(0, max_attempts)):
        if not issues:
            return []
        try:
            operation = repair(repair_prompt(issues))
            if timeout_seconds is None:
                await operation
            else:
                await asyncio.wait_for(operation, timeout=timeout_seconds)
        except TimeoutError:
            logger.warning("Validation repair attempt %d timed out.", attempt + 1)
        issues = validator()
    return issues


def finalize_checkpoint(
    checkpoint: CheckpointManager,
    task_key: str,
    *,
    valid: bool,
) -> None:
    if valid:
        checkpoint.mark_complete(task_key)
    else:
        checkpoint.clear(task_key)


def remove_invalid_files(paths: list[str]) -> None:
    for path in paths:
        with contextlib.suppress(OSError):
            os.remove(path)


def _record_trajectory_stage(
    config: AuditConfig, stage: int, description: str
) -> None:
    root = config.trajectory_root
    if root is None:
        return
    try:
        root.system(f"Stage {stage}: {description}", extra={"stage": stage})
    except Exception as exc:  # pragma: no cover - defensive
        logger.warning("Could not record stage %d in the trajectory: %s", stage, exc)


@dataclass
class StageProgress:
    stage: int
    state_store: StageStateStore
    reporter: object | None

    def update(
        self,
        *,
        items_done: int = 0,
        items_total: int = 0,
        detail: str = "",
    ) -> None:
        self.state_store.update(
            self.stage,
            items_done=items_done,
            items_total=items_total,
            detail=detail,
        )
        if self.reporter and hasattr(self.reporter, "stage_progress"):
            self.reporter.stage_progress(
                self.stage,
                items_done=items_done,
                items_total=items_total,
                detail=detail,
            )


@contextlib.asynccontextmanager
async def stage_span(
    config: AuditConfig,
    reporter: object | None,
    state_store: StageStateStore,
    stage: int,
    description: str,
) -> AsyncIterator[StageProgress]:
    """Run one stage with consistent trajectory, progress, and persisted state."""
    _record_trajectory_stage(config, stage, description)
    state_store.begin(stage, description)
    if reporter and hasattr(reporter, "begin_stage"):
        reporter.begin_stage(stage, description)
    progress = StageProgress(stage=stage, state_store=state_store, reporter=reporter)
    try:
        yield progress
    except BaseException as exc:
        state_store.fail(stage, exc)
        raise
    else:
        state_store.complete(stage)
        if reporter and hasattr(reporter, "end_stage"):
            reporter.end_stage(stage)
