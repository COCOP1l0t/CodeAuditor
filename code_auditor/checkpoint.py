from __future__ import annotations

import os
import re
from pathlib import Path
from urllib.parse import quote, unquote

from .logger import get_logger

logger = get_logger("checkpoint")

# A task key is a stage id (``stage2``) plus an optional ``:``-separated suffix
# (``stage5:H-01``). Marker names must be unique, reversible, single path
# components, so the key is encoded as ``<stage>--<percent-escaped suffix>``:
# the stage part never contains ``--``, which makes the split unambiguous, and
# percent-escaping makes the suffix reversible for *any* character (``:``, ``/``,
# NUL, unicode). Distinct task keys therefore never share a marker name, and the
# suffix is never able to escape ``.markers/``.
_STAGE_RE = re.compile(r"stage[0-9]{1,2}")
_TASK_KEY_RE = re.compile(r"stage[0-9]{1,2}(?::[\s\S]*)?")
_MARKER_SEPARATOR = "--"
# Percent-escaped names are ASCII, so this bounds both chars and bytes.
_MAX_MARKER_NAME = 200
# Keep the common case readable: ``stage5:H-01`` -> ``stage5--H-01``.
_QUOTE_SAFE = "-._"
# Content that may be joined into a path as a single component.
_SAFE_COMPONENT_RE = re.compile(r"[A-Za-z0-9._-]+")
_STAGE4_KEY_PREFIX = "stage4:"


def _encode_task_key(task_key: str) -> str | None:
    """Return the marker name for a task key, or ``None`` when untrackable.

    The encoding is injective: a bare key is its own name, and a suffixed key is
    ``<stage>--`` plus the percent-escaped suffix, which the first ``--`` splits
    back unambiguously (:func:`_decode_marker_name`). Keys whose encoded name
    would exceed the name budget are untracked rather than truncated.
    """
    if _TASK_KEY_RE.fullmatch(task_key) is None:
        return None
    stage, separator, suffix = task_key.partition(":")
    if not separator:
        return stage
    name = f"{stage}{_MARKER_SEPARATOR}{quote(suffix, safe=_QUOTE_SAFE)}"
    if len(name) > _MAX_MARKER_NAME:
        return None
    return name


def _decode_marker_name(name: str) -> str | None:
    """Inverse of :func:`_encode_task_key` for markers written by this scheme.

    Returns ``None`` for names written before the reversible encoding
    (``stage5-H-01``) and for anything else that is not a marker name.
    """
    stage, separator, encoded = name.partition(_MARKER_SEPARATOR)
    if not separator:
        return name if _STAGE_RE.fullmatch(name) else None
    if _STAGE_RE.fullmatch(stage) is None:
        return None
    return f"{stage}:{unquote(encoded)}"


def _legacy_marker_name(task_key: str) -> str | None:
    """Return the pre-reversible ``:``→``-`` marker name for a task key.

    Only a key with a single ``:`` (the stage separator) was encoded
    unambiguously by the old scheme, so only those may consult a leftover legacy
    marker; every other key re-runs instead of borrowing a marker that the old,
    lossy encoding may have written for a different task. A name that is itself
    a valid new-style marker (contains the ``--`` boundary) is never treated as
    legacy, so the two schemes cannot read each other's names.
    """
    if task_key.count(":") != 1:
        return None
    name = task_key.replace(":", "-")
    if _MARKER_SEPARATOR in name or _SAFE_COMPONENT_RE.fullmatch(name) is None:
        return None
    return name


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
        if os.path.exists(resolved):
            logger.debug("Checkpoint hit: %s -> %s", task_key, resolved)
            return True
        # Runs started before the reversible encoding have markers named by the
        # old lossy scheme; read them so an in-flight audit still resumes.
        legacy = self._legacy_marker_path(task_key)
        if legacy is not None and os.path.exists(legacy):
            logger.debug("Legacy checkpoint hit: %s -> %s", task_key, legacy)
            return True
        return False

    def mark_complete(self, task_key: str) -> None:
        if not self._needs_marker(task_key):
            logger.debug("Checkpoint tracked by output file: %s", task_key)
            return
        marker_path = self._marker_path(task_key)
        if marker_path is None:
            return
        os.makedirs(self._markers_dir, exist_ok=True)
        Path(marker_path).touch()

    def clear(self, task_key: str) -> None:
        if not self._needs_marker(task_key):
            return
        marker_path = self._marker_path(task_key)
        if marker_path is None:
            return
        # Retire a leftover legacy marker too; otherwise it would keep reporting
        # this task complete on the next resume.
        for path in (marker_path, self._legacy_marker_path(task_key)):
            if path is not None:
                Path(path).unlink(missing_ok=True)

    def _resolve(self, task_key: str) -> str | None:
        if task_key == "stage1":
            return os.path.join(self._output_dir, "stage1-security-context", "stage-1-security-context.json")
        if task_key == "stage2":
            return self._marker_path(task_key)
        if task_key.startswith("stage3:"):
            return self._marker_path(task_key)
        if task_key.startswith(_STAGE4_KEY_PREFIX):
            marker = self._marker_path(task_key)
            if marker is None:
                return None
            if os.path.exists(marker):
                return marker
            # Fall back to pending file for runs that predate marker-based tracking.
            filename = task_key[len(_STAGE4_KEY_PREFIX):]
            if (
                _SAFE_COMPONENT_RE.fullmatch(filename) is None
                or filename in {".", ".."}
            ):
                logger.warning(
                    "Ignoring stage4 finding name that is not a safe path component: %s",
                    filename,
                )
                return None
            return os.path.join(self._output_dir, "stage4-vulnerabilities", "_pending", filename)
        if task_key.startswith("stage5:"):
            return self._marker_path(task_key)
        if task_key.startswith("stage6:"):
            return self._marker_path(task_key)
        logger.warning("Unknown checkpoint task key: %s", task_key)
        return None

    def _needs_marker(self, task_key: str) -> bool:
        return task_key == "stage2" or task_key.startswith("stage3:") or task_key.startswith("stage4:") or task_key.startswith("stage5:") or task_key.startswith("stage6:")

    def _marker_path(self, task_key: str) -> str | None:
        """Return the marker file path, or ``None`` for an untrackable key.

        The name is a reversible, single-component encoding of the key, so two
        distinct keys can never share a marker and a key can never walk out of
        ``.markers/``. Untrackable keys (wrong stage shape, or a name over the
        budget) are not checkpointed, so a resume re-runs them instead of
        skipping them as complete.
        """
        name = _encode_task_key(task_key)
        if name is None:
            logger.warning("Ignoring untrackable checkpoint task key: %s", task_key)
            return None
        return os.path.join(self._markers_dir, name)

    def _legacy_marker_path(self, task_key: str) -> str | None:
        name = _legacy_marker_name(task_key)
        if name is None:
            return None
        return os.path.join(self._markers_dir, name)
