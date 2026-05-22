from __future__ import annotations

import os
import re

from ..agent import run_agent
from ..checkpoint import CheckpointManager
from ..config import AnalysisUnit, AuditConfig
from ..logger import get_logger
from ..prompts import load_prompt
from ..utils import format_validation_issues, list_matching_files, run_parallel_limited
from ..validation.stage3 import validate_stage3_file
from ..wiki import build_wiki_context

logger = get_logger("stage3")


def _task_key(unit: AnalysisUnit) -> str:
    return f"stage3:{unit.id}"


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
    result_dir = os.path.join(config.output_dir, "stage3-findings")
    log_file = os.path.join(result_dir, "logs", f"{unit.id}.log")
    escaped_id = re.escape(unit.id)
    finding_pattern = re.compile(rf"^{escaped_id}-F-\d+\.json$")
    progress = f"[{unit_index}/{total_units}]" if total_units else ""

    if checkpoint.is_complete(key):
        logger.info("Stage 3 %s: %s already complete, skipping.", progress, unit.id)
        return list_matching_files(result_dir, finding_pattern)

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
    for finding_file in finding_files:
        issues = validate_stage3_file(finding_file)
        if not issues:
            continue

        logger.warning("Stage 3: Validation failed for %s\n%s", finding_file, format_validation_issues(issues))
        repair_prompt = (
            f"The finding file at `{finding_file}` failed validation. "
            f"Please fix all issues listed below:\n\n```\n{format_validation_issues(issues)}\n```"
        )
        await run_agent(repair_prompt, config, cwd=config.target, max_turns=10, log_file=log_file)

        issues = validate_stage3_file(finding_file)
        if issues:
            logger.warning("Stage 3: Repair failed for %s\n%s", finding_file, format_validation_issues(issues))

    checkpoint.mark_complete(key)
    logger.info("Stage 3 %s: %s complete. Findings: %d", progress, unit.id, len(finding_files))
    return finding_files


async def run_stage3(
    units: list[AnalysisUnit],
    config: AuditConfig,
    checkpoint: CheckpointManager,
    auditing_focus_path: str,
    vuln_criteria_path: str,
) -> list[str]:
    if not units:
        logger.warning("Stage 3: No analysis units to process.")
        return []

    total = len(units)
    logger.info("Stage 3: Starting bug discovery across %d analysis units (max parallel: %d).", total, config.max_parallel)

    results = await run_parallel_limited(
        units,
        config.max_parallel,
        lambda unit, idx: _run_unit(
            unit, config, checkpoint, auditing_focus_path, vuln_criteria_path,
            unit_index=idx + 1, total_units=total,
        ),
    )

    all_finding_files: list[str] = []
    for i, (status, value, error) in enumerate(results):
        if i >= len(units):
            continue
        if status == "rejected":
            logger.error("Stage 3: %s failed: %s", units[i].id, error)
            continue
        if value:
            all_finding_files.extend(value)

    logger.info("Stage 3 complete. Total bug finding files: %s", len(all_finding_files))
    return all_finding_files
