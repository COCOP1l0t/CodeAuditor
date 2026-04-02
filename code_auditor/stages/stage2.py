from __future__ import annotations

import os

from ..agent import run_agent
from ..checkpoint import CheckpointManager
from ..config import AnalysisUnit, AuditConfig
from ..logger import get_logger
from ..parsing.stage2 import parse_au_files, parse_auditing_focus
from ..prompts import load_prompt
from ..utils import format_validation_issues
from ..validation.stage2 import validate_stage2_dir

logger = get_logger("stage2")
_TASK_KEY = "stage2"


async def run_stage2(
    config: AuditConfig,
    checkpoint: CheckpointManager,
    auditing_focus_path: str,
) -> list[AnalysisUnit]:
    result_dir = os.path.join(config.output_dir, "stage-2-details")
    os.makedirs(result_dir, exist_ok=True)

    if checkpoint.is_complete(_TASK_KEY):
        logger.info("Stage 2 already complete, loading existing output.")
        return parse_au_files(result_dir)

    scope_modules, hot_spots = parse_auditing_focus(auditing_focus_path)

    prompt = load_prompt("stage2.md", {
        "target_path": config.target,
        "result_dir": result_dir,
        "user_instructions": config.scope or "No additional scope constraints.",
        "scope_modules": scope_modules or "No scope information available.",
        "historical_hot_spots": hot_spots or "No historical data available.",
    })

    await run_agent(prompt, config, cwd=config.target)

    # Validate the output directory
    issues = validate_stage2_dir(result_dir)
    if issues:
        logger.warning(
            "Stage 2 validation issues:\n%s", format_validation_issues(issues),
        )
        repair_prompt = (
            f"The analysis unit files in `{result_dir}` failed validation. "
            "Please fix all issues listed below:\n\n"
            f"```\n{format_validation_issues(issues)}\n```"
        )
        await run_agent(repair_prompt, config, cwd=config.target, max_turns=10)

        issues = validate_stage2_dir(result_dir)
        if issues:
            logger.warning(
                "Stage 2 validation still has issues after repair:\n%s",
                format_validation_issues(issues),
            )

    checkpoint.mark_complete(_TASK_KEY)
    units = parse_au_files(result_dir)
    logger.info("Stage 2 complete. Analysis units: %s", ", ".join(u.id for u in units))
    return units
