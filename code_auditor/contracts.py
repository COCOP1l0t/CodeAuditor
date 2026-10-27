"""Shared JSON contracts for stage artifacts.

The constants here are the canonical field lists used by validators and by
stage/DB readers. Prompt templates still render human-readable schemas, but a
contract test keeps those templates aligned with this module.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

STAGE3_REQUIRED_FIELDS = (
    "finding_id",
    "title",
    "location",
    "vulnerability_class",
    "root_cause",
    "preliminary_severity",
)
STAGE3_SEVERITIES = frozenset({"critical", "high", "medium", "low"})

STAGE4_REQUIRED_FIELDS = (
    "id",
    "title",
    "location",
    "data_flow_trace",
    "cwe_id",
    "vulnerability_class",
    "trigger",
    "cvss_score",
)
STAGE4_DATA_FLOW_TRACE_FIELDS = (
    "entry_point",
    "propagation_chain",
    "neutralizing_checks",
    "sink",
)


def read_json_object(path: str | Path) -> dict[str, Any]:
    """Read one JSON object with a stable contract error type."""
    target = Path(path)
    try:
        value = json.loads(target.read_text(encoding="utf-8", errors="replace"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot read JSON object {target}: {exc}") from exc
    if not isinstance(value, dict):
        raise ValueError(f"JSON root must be an object: {target}")
    return value
