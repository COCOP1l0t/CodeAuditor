from __future__ import annotations

import os
from pathlib import Path

from .logger import get_logger

logger = get_logger("checkpoint")


class CheckpointManager:
    def __init__(self, output_dir: str, resume: bool) -> None:
        self._output_dir = output_dir
        self._resume = resume
        self._markers_dir = os.path.join(output_dir, ".markers")

    def is_complete(self, task_key: str) -> bool:
        if not self._resume:
            return False
        resolved = self._resolve(task_key)
        if resolved is None:
            return False
        exists = os.path.exists(resolved)
        if exists:
            logger.debug("Checkpoint hit: %s -> %s", task_key, resolved)
        return exists

    def mark_complete(self, task_key: str) -> None:
        if not self._needs_marker(task_key):
            logger.debug("Checkpoint tracked by output file: %s", task_key)
            return
        os.makedirs(self._markers_dir, exist_ok=True)
        Path(self._marker_path(task_key)).touch()

    def _resolve(self, task_key: str) -> str | None:
        if task_key == "stage1":
            return os.path.join(self._output_dir, "stage-1-details", "stage-1-security-context.json")
        if task_key == "stage2":
            return self._marker_path(task_key)
        if task_key.startswith("stage3:"):
            return self._marker_path(task_key)
        if task_key.startswith("stage4:"):
            marker = self._marker_path(task_key)
            if os.path.exists(marker):
                return marker
            # Fall back to pending file for runs that predate marker-based tracking.
            filename = task_key[len("stage4:"):]
            return os.path.join(self._output_dir, "stage-4-details", "_pending", filename)
        if task_key.startswith("stage5:"):
            return self._marker_path(task_key)
        if task_key.startswith("stage6:"):
            return self._marker_path(task_key)
        logger.warning("Unknown checkpoint task key: %s", task_key)
        return None

    def _needs_marker(self, task_key: str) -> bool:
        return task_key == "stage2" or task_key.startswith("stage3:") or task_key.startswith("stage4:") or task_key.startswith("stage5:") or task_key.startswith("stage6:")

    def _marker_path(self, task_key: str) -> str:
        return os.path.join(self._markers_dir, task_key.replace(":", "-"))
