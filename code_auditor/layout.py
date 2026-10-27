"""Canonical on-disk layout for audit stages and their artifacts."""

from __future__ import annotations

import os

STAGE1_DIRNAME = "stage1-security-context"
STAGE2_DIRNAME = "stage2-analysis-units"
STAGE3_DIRNAME = "stage3-findings"
STAGE4_DIRNAME = "stage4-vulnerabilities"
STAGE5_DIRNAME = "stage5-pocs"
STAGE6_DIRNAME = "stage6-disclosures"
MARKERS_DIRNAME = ".markers"
STAGE_STATE_FILENAME = ".stage-state.json"

STAGE_DIRNAMES = {
    1: STAGE1_DIRNAME,
    2: STAGE2_DIRNAME,
    3: STAGE3_DIRNAME,
    4: STAGE4_DIRNAME,
    5: STAGE5_DIRNAME,
    6: STAGE6_DIRNAME,
}

STAGE1_RECORD_FILENAME = "stage-1-security-context.json"
STAGE1_FOCUS_FILENAME = "auditing-focus.md"
STAGE1_CRITERIA_FILENAME = "vulnerability-criteria.md"


def stage_dir(output_dir: str, stage: int) -> str:
    try:
        dirname = STAGE_DIRNAMES[stage]
    except KeyError:
        raise ValueError(f"Unknown audit stage: {stage}") from None
    return os.path.join(output_dir, dirname)


def stage1_paths(output_dir: str) -> dict[str, str]:
    directory = stage_dir(output_dir, 1)
    return {
        "directory": directory,
        "record": os.path.join(directory, STAGE1_RECORD_FILENAME),
        "focus": os.path.join(directory, STAGE1_FOCUS_FILENAME),
        "criteria": os.path.join(directory, STAGE1_CRITERIA_FILENAME),
        "log": os.path.join(directory, "agent.log"),
    }


def stage2_paths(output_dir: str) -> dict[str, str]:
    directory = stage_dir(output_dir, 2)
    return {"directory": directory, "log": os.path.join(directory, "agent.log")}


def stage3_paths(output_dir: str) -> dict[str, str]:
    directory = stage_dir(output_dir, 3)
    return {
        "directory": directory,
        "logs": os.path.join(directory, "logs"),
    }


def stage4_paths(output_dir: str) -> dict[str, str]:
    directory = stage_dir(output_dir, 4)
    return {
        "directory": directory,
        "pending": os.path.join(directory, "_pending"),
        "logs": os.path.join(directory, "logs"),
    }


def stage5_paths(output_dir: str) -> dict[str, str]:
    return {"directory": stage_dir(output_dir, 5)}


def stage6_paths(output_dir: str) -> dict[str, str]:
    return {"directory": stage_dir(output_dir, 6)}


def markers_dir(output_dir: str) -> str:
    return os.path.join(output_dir, MARKERS_DIRNAME)


def stage_state_path(output_dir: str) -> str:
    return os.path.join(output_dir, STAGE_STATE_FILENAME)


def checkpoint_key(stage: int, *parts: str) -> str:
    if stage in {1, 2}:
        if parts:
            raise ValueError(f"Stage {stage} does not accept checkpoint parts")
        return f"stage{stage}"
    if stage not in STAGE_DIRNAMES:
        raise ValueError(f"Unknown audit stage: {stage}")
    if not parts:
        raise ValueError(f"Stage {stage} checkpoint requires a task identifier")
    return f"stage{stage}:" + ":".join(parts)
