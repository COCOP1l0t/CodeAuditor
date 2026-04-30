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
from ..wiki import build_wiki_context

logger = get_logger("stage2")
_TASK_KEY = "stage2"


async def run_stage2(
    config: AuditConfig,
    checkpoint: CheckpointManager,
    auditing_focus_path: str,
) -> list[AnalysisUnit]:
    result_dir = os.path.join(config.output_dir, "stage2-analysis-units")
    os.makedirs(result_dir, exist_ok=True)
    log_file = os.path.join(result_dir, "agent.log")

    if checkpoint.is_complete(_TASK_KEY):
        logger.info("Stage 2 already complete, loading existing output.")
        return parse_au_files(result_dir)

    # On resume, check for intermediate results from a crashed previous run.
    # The agent may have written AU files before the checkpoint marker was set.
    if config.resume and parse_au_files(result_dir):
        logger.info("Stage 2: Found existing intermediate results. Validating.")
        issues = validate_stage2_dir(result_dir, max_aus=config.target_au_count)
        if not issues:
            logger.info("Stage 2: Existing output is valid. Skipping agent re-run.")
            checkpoint.mark_complete(_TASK_KEY)
            units = parse_au_files(result_dir)
            logger.info("Stage 2 complete (restored). Analysis units: %s", ", ".join(u.id for u in units))
            return units
        logger.warning(
            "Stage 2: Existing output has validation issues:\n%s",
            format_validation_issues(issues),
        )
        logger.info("Stage 2: Running repair agent to fix validation issues.")
        repair_prompt = (
            f"The analysis unit files in `{result_dir}` failed validation. "
            "Please fix all issues listed below:\n\n"
            f"```\n{format_validation_issues(issues)}\n```"
        )
        await run_agent(repair_prompt, config, cwd=config.target, max_turns=10, log_file=log_file)
        issues = validate_stage2_dir(result_dir, max_aus=config.target_au_count)
        if not issues:
            checkpoint.mark_complete(_TASK_KEY)
            units = parse_au_files(result_dir)
            logger.info("Stage 2 complete (repaired). Analysis units: %s", ", ".join(u.id for u in units))
            return units
        logger.warning(
            "Stage 2: Repair failed, falling through to full re-run.\n%s",
            format_validation_issues(issues),
        )

    logger.info("Stage 2: Starting codebase decomposition (target AU count: %d).", config.target_au_count)

    scope_modules, hot_spots = parse_auditing_focus(auditing_focus_path)

    logger.info("Stage 2: Running agent to enumerate, triage, and create analysis units.")
    prompt = load_prompt("stage2.md", {
        "target_path": config.target,
        "result_dir": result_dir,
        "user_instructions": config.scope or "No additional scope constraints.",
        "scope_modules": scope_modules or "No scope information available.",
        "historical_hot_spots": hot_spots or "No historical data available.",
        "target_au_count": str(config.target_au_count),
        "wiki_context": build_wiki_context(config, stage=2),
    })

    await run_agent(prompt, config, cwd=config.target, max_turns=200, log_file=log_file)

    logger.info("Stage 2: Agent finished. Validating output.")
    issues = validate_stage2_dir(result_dir, max_aus=config.target_au_count)
    if issues:
        logger.warning(
            "Stage 2 validation issues:\n%s", format_validation_issues(issues),
        )
        logger.info("Stage 2: Running repair agent to fix validation issues.")
        repair_prompt = (
            f"The analysis unit files in `{result_dir}` failed validation. "
            "Please fix all issues listed below:\n\n"
            f"```\n{format_validation_issues(issues)}\n```"
        )
        await run_agent(repair_prompt, config, cwd=config.target, max_turns=10, log_file=log_file)

        issues = validate_stage2_dir(result_dir, max_aus=config.target_au_count)
        if issues:
            logger.warning(
                "Stage 2 validation still has issues after repair:\n%s",
                format_validation_issues(issues),
            )

    checkpoint.mark_complete(_TASK_KEY)
    units = parse_au_files(result_dir)
    logger.info("Stage 2 complete. Analysis units: %s", ", ".join(u.id for u in units))
    return units
