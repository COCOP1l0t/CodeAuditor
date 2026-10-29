"""Persistent stage lifecycle state used by history and resume diagnostics."""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .layout import stage_state_path
from .logger import get_logger
from .secure_fs import write_private_bytes_atomic

logger = get_logger("stage_state")


@dataclass
class StageStatus:
    stage: int
    status: str = "pending"
    detail: str = ""
    items_done: int = 0
    items_total: int = 0
    started_at: float | None = None
    ended_at: float | None = None
    error: str = ""

    def public(self) -> dict[str, Any]:
        return {
            "stage": self.stage,
            "status": self.status,
            "detail": self.detail,
            "items_done": self.items_done,
            "items_total": self.items_total,
            "started_at": self.started_at,
            "ended_at": self.ended_at,
            "error": self.error,
        }


def read_stage_state(output_dir: str) -> dict[int, dict[str, Any]]:
    path = stage_state_path(output_dir)
    try:
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError, UnicodeError):
        return {}
    raw_stages = payload.get("stages") if isinstance(payload, dict) else None
    if not isinstance(raw_stages, dict):
        return {}
    result: dict[int, dict[str, Any]] = {}
    for raw_stage, value in raw_stages.items():
        try:
            stage = int(raw_stage)
        except (TypeError, ValueError):
            continue
        if 0 <= stage <= 6 and isinstance(value, dict):
            result[stage] = dict(value)
    return result


class StageStateStore:
    def __init__(self, output_dir: str) -> None:
        self.output_dir = output_dir
        existing = read_stage_state(output_dir)
        self._stages: dict[int, StageStatus] = {}
        for stage in range(7):
            value = existing.get(stage, {})
            self._stages[stage] = StageStatus(
                stage=stage,
                status=str(value.get("status") or "pending"),
                detail=str(value.get("detail") or ""),
                items_done=int(value.get("items_done") or 0),
                items_total=int(value.get("items_total") or 0),
                started_at=value.get("started_at"),
                ended_at=value.get("ended_at"),
                error=str(value.get("error") or ""),
            )

    def reset(self, *, preserve_completed: bool = False) -> None:
        """Start a fresh execution while optionally retaining completed timing."""
        previous = dict(self._stages) if preserve_completed else {}
        self._stages = {
            stage: (
                previous[stage]
                if previous.get(stage) is not None
                and previous[stage].status == "done"
                else StageStatus(stage=stage)
            )
            for stage in range(7)
        }
        self._write()

    def clear(self, stage: int) -> None:
        """Reset one stage while preserving the others."""
        self._stages[stage] = StageStatus(stage=stage)
        self._write()

    def begin(self, stage: int, description: str) -> None:
        if self._stages[stage].status == "done":
            return
        self._stages[stage] = StageStatus(
            stage=stage,
            status="running",
            detail=description,
            started_at=time.time(),
        )
        self._write()

    def update(
        self,
        stage: int,
        *,
        items_done: int = 0,
        items_total: int = 0,
        detail: str = "",
    ) -> None:
        state = self._stages[stage]
        state.items_done = max(0, int(items_done))
        state.items_total = max(0, int(items_total))
        if detail:
            state.detail = detail
        self._write()

    def complete(self, stage: int) -> None:
        state = self._stages[stage]
        if state.status == "done" and state.ended_at is not None:
            return
        state.status = "done"
        state.ended_at = time.time()
        self._write()

    def fail(self, stage: int, error: BaseException) -> None:
        state = self._stages[stage]
        state.status = "failed"
        state.error = f"{type(error).__name__}: {error}"[:2000]
        state.ended_at = time.time()
        self._write()

    def snapshot(self) -> list[dict[str, Any]]:
        return [self._stages[stage].public() for stage in range(7)]

    def _write(self) -> None:
        payload = {
            "schema_version": 1,
            "stages": {
                str(stage): state.public() for stage, state in self._stages.items()
            },
        }
        try:
            write_private_bytes_atomic(
                stage_state_path(self.output_dir),
                (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode("utf-8"),
            )
        except Exception as exc:  # observational state must not fail the audit
            logger.warning("Could not persist stage state: %s", exc)
