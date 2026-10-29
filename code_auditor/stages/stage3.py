from __future__ import annotations

import os
import re
from contextlib import suppress

from ..agent import run_agent
from ..checkpoint import CheckpointManager
from ..config import AnalysisUnit, AuditConfig
from ..layout import checkpoint_key, stage3_paths
from ..logger import get_logger
from ..prompts import load_prompt
from ..stage_runtime import finalize_checkpoint, repair_until_valid
from ..utils import (
    collect_parallel_results,
    format_validation_issues,
    list_matching_files,
    run_parallel_limited,
)
from ..validation.stage3 import validate_stage3_file
from ..wiki import build_wiki_context

logger = get_logger("stage3")


def _task_key(unit: AnalysisUnit) -> str:
    return checkpoint_key(3, unit.id)


async def _run_unit(
    unit: AnalysisUnit,
    config: AuditConfig,
    checkpoint: CheckpointManager,
    auditing_focus_path: str,
    vuln_criteria_path: str,
    unit_index: int = 0,
    total_units: int = 0,
) -> list[str]:
    key = _task_key(unit)
    paths = stage3_paths(config.output_dir)
    result_dir = paths["directory"]
    log_file = os.path.join(paths["logs"], f"{unit.id}.log")
    escaped_id = re.escape(unit.id)
    finding_pattern = re.compile(rf"^{escaped_id}-F-\d+\.json$")
    progress = f"[{unit_index}/{total_units}]" if total_units else ""

    if checkpoint.is_complete(key):
        finding_files = list_matching_files(result_dir, finding_pattern)
        invalid_files = [
            finding_file
            for finding_file in finding_files
            if validate_stage3_file(finding_file)
        ]
        if not invalid_files:
            logger.info("Stage 3 %s: %s already complete, skipping.", progress, unit.id)
            return finding_files

        logger.warning(
            "Stage 3 %s: %s has invalid checkpointed findings; deleting them and rerunning.",
            progress,
            unit.id,
        )
        for finding_file in finding_files:
            with suppress(OSError):
                os.remove(finding_file)
        checkpoint.clear(key)

    logger.info("Stage 3 %s: Starting bug discovery for %s.", progress, unit.id)
    prompt = load_prompt("stage3.md", {
        "au_file_path": unit.au_file_path,
        "result_dir": result_dir,
        "finding_prefix": unit.id,
        "auditing_focus_path": auditing_focus_path,
        "vuln_criteria_path": vuln_criteria_path,
        "wiki_context": build_wiki_context(config, stage=3),
    })

    await run_agent(prompt, config, cwd=config.target, max_turns=200, log_file=log_file)

    logger.info("Stage 3 %s: Agent finished for %s. Validating findings.", progress, unit.id)
    finding_files = list_matching_files(result_dir, finding_pattern)
    valid_finding_files: list[str] = []
    had_unresolved_validation = False
    for finding_file in finding_files:
        async def repair(prompt: str) -> object:
            return await run_agent(
                prompt,
                config,
                cwd=config.target,
                max_turns=10,
                log_file=log_file,
            )

        issues = await repair_until_valid(
            validator=lambda path=finding_file: validate_stage3_file(path),
            repair=repair,
            repair_prompt=lambda current, path=finding_file: (
                f"The finding file at `{path}` failed validation. "
                "Please fix all issues listed below:\n\n"
                f"```\n{format_validation_issues(current)}\n```"
            ),
            max_attempts=1,
            timeout_seconds=300,
        )
        if issues:
            logger.warning(
                "Stage 3: Repair failed for %s\n%s",
                finding_file,
                format_validation_issues(issues),
            )
            with suppress(OSError):
                os.remove(finding_file)
            had_unresolved_validation = True
            continue
        valid_finding_files.append(finding_file)

    finalize_checkpoint(
        checkpoint, key, valid=not had_unresolved_validation
    )
    logger.info("Stage 3 %s: %s complete. Findings: %d", progress, unit.id, len(valid_finding_files))
    return valid_finding_files


async def run_stage3(
    units: list[AnalysisUnit],
    config: AuditConfig,
    checkpoint: CheckpointManager,
    auditing_focus_path: str,
    vuln_criteria_path: str,
    progress: object | None = None,
) -> list[str]:
    if not units:
        logger.warning("Stage 3: No analysis units to process.")
        return []

    total = len(units)
    logger.info("Stage 3: Starting bug discovery across %d analysis units (max parallel: %d).", total, config.max_parallel)

    completed = 0

    def task_complete(index: int, unit: AnalysisUnit) -> None:
        nonlocal completed
        completed += 1
        if progress is not None:
            progress.update(
                items_done=completed,
                items_total=total,
                detail=f"Analyzed {completed}/{total} analysis units",
            )

    results = await run_parallel_limited(
        units,
        config.max_parallel,
        lambda unit, idx: _run_unit(
            unit, config, checkpoint, auditing_focus_path, vuln_criteria_path,
            unit_index=idx + 1, total_units=total,
        ),
        on_complete=task_complete,
    )

    finding_groups = collect_parallel_results(
        results,
        units,
        stage="stage3",
        config=config,
        logger=logger,
        item_id=lambda unit: unit.id,
    )
    all_finding_files = [path for group in finding_groups for path in group]

    logger.info("Stage 3 complete. Total bug finding files: %s", len(all_finding_files))
    return all_finding_files
