from __future__ import annotations

import os
import re

from ..agent import run_agent
from ..checkpoint import CheckpointManager
from ..config import AnalysisUnit, AuditConfig
from ..layout import checkpoint_key, stage2_paths
from ..logger import get_logger
from ..parsing.stage2 import parse_au_files, parse_auditing_focus
from ..prompts import load_prompt
from ..stage_runtime import finalize_checkpoint, repair_until_valid
from ..utils import format_validation_issues
from ..validation.stage2 import validate_stage2_dir
from ..wiki import build_wiki_context

logger = get_logger("stage2")
_TASK_KEY = checkpoint_key(2)
_AU_FILENAME = re.compile(r"^AU-\d+\.json$")


def _clear_existing_units(result_dir: str) -> None:
    """Remove stale Stage 2 artifacts before a full re-run.

    The agent overwrites AU-1..AU-N but never deletes higher-numbered files, so
    leftovers from an earlier run would otherwise survive as extra analysis
    units and be merged with the new set.
    """
    try:
        names = os.listdir(result_dir)
    except OSError:
        return
    for name in names:
        if name != "triage.json" and not _AU_FILENAME.match(name):
            continue
        try:
            os.remove(os.path.join(result_dir, name))
        except OSError:
            continue


async def run_stage2(
    config: AuditConfig,
    checkpoint: CheckpointManager,
    auditing_focus_path: str,
) -> list[AnalysisUnit]:
    paths = stage2_paths(config.output_dir)
    result_dir = paths["directory"]
    os.makedirs(result_dir, exist_ok=True)
    log_file = paths["log"]

    def validator():
        return validate_stage2_dir(result_dir, max_aus=config.target_au_count)

    async def repair(prompt: str) -> object:
        return await run_agent(
            prompt, config, cwd=config.target, max_turns=10, log_file=log_file
        )

    def repair_prompt(issues):
        return (
            f"The analysis unit files in `{result_dir}` failed validation. "
            "Please fix all issues listed below:\n\n"
            f"```\n{format_validation_issues(issues)}\n```"
        )

    if checkpoint.is_complete(_TASK_KEY):
        issues = validator()
        if not issues:
            logger.info("Stage 2 already complete, loading existing output.")
            return parse_au_files(result_dir)
        # The marker was written by an older run that accepted a failed repair;
        # re-validate instead of trusting it, and re-run when the output is
        # still invalid.
        logger.warning(
            "Stage 2: checkpointed output is invalid; rerunning.\n%s",
            format_validation_issues(issues),
        )
        checkpoint.clear(_TASK_KEY)

    # On resume, check for intermediate results from a crashed previous run.
    # The agent may have written AU files before the checkpoint marker was set.
    if config.resume and parse_au_files(result_dir):
        logger.info("Stage 2: Found existing intermediate results. Validating.")
        issues = validator()
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
        issues = await repair_until_valid(
            validator=validator,
            repair=repair,
            repair_prompt=repair_prompt,
            max_attempts=1,
        )
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
    # A fresh full run must not merge with stale files from a previous attempt.
    _clear_existing_units(result_dir)

    scope_modules, hot_spots = parse_auditing_focus(auditing_focus_path)
    if config.target_au_count <= 0:
        au_count_directive = (
            "no fixed ceiling — select as many areas as genuinely warrant deep "
            "security analysis, erring on the side of broader coverage"
        )
    else:
        au_count_directive = str(config.target_au_count)

    logger.info("Stage 2: Running agent to enumerate, triage, and create analysis units.")
    prompt = load_prompt("stage2.md", {
        "target_path": config.target,
        "result_dir": result_dir,
        "user_instructions": config.scope or "No additional scope constraints.",
        "scope_modules": scope_modules or "No scope information available.",
        "historical_hot_spots": hot_spots or "No historical data available.",
        "target_au_count": au_count_directive,
        "wiki_context": build_wiki_context(config, stage=2),
    })

    await run_agent(prompt, config, cwd=config.target, max_turns=200, log_file=log_file)

    logger.info("Stage 2: Agent finished. Validating output.")
    issues = validator()
    if issues:
        logger.warning(
            "Stage 2 validation issues:\n%s", format_validation_issues(issues),
        )
        logger.info("Stage 2: Running repair agent to fix validation issues.")
        issues = await repair_until_valid(
            validator=validator,
            repair=repair,
            repair_prompt=repair_prompt,
            max_attempts=1,
        )
        if issues:
            logger.warning(
                "Stage 2 validation still has issues after repair:\n%s",
                format_validation_issues(issues),
            )

    units = parse_au_files(result_dir)
    if issues:
        # Do not checkpoint invalid output or feed malformed units downstream:
        # leaving the marker unset lets a resume re-run Stage 2, and returning
        # nothing makes the orchestrator fail the run loudly instead of
        # dispatching Stage 3 agents against invalid analysis units.
        logger.error(
            "Stage 2 finished with validation issues; not marking it complete "
            "and discarding %d unvalidated unit(s).",
            len(units),
        )
        return []
    finalize_checkpoint(checkpoint, _TASK_KEY, valid=not issues)
    logger.info("Stage 2 complete. Analysis units: %s", ", ".join(u.id for u in units))
    return units
