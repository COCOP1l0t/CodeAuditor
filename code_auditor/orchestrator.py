from __future__ import annotations

import os

from .checkpoint import CheckpointManager
from .config import AnalysisUnit, AuditConfig
from .logger import get_logger
from .parsing.stage2 import parse_au_files
from .stages.stage0 import run_setup
from .stages.stage1 import Stage1Output, run_stage1
from .stages.stage2 import run_stage2
from .stages.stage3 import run_stage3
from .stages.stage4 import run_stage4
from .utils import list_json_files

logger = get_logger("orchestrator")


async def run_audit(config: AuditConfig) -> None:
    checkpoint = CheckpointManager(config.output_dir, config.resume)

    if config.resume:
        logger.info("Resume mode enabled. Existing output files and markers will be reused.")

    # Stage 0: setup
    if 0 not in config.skip_stages:
        await run_setup(config)

    # Stage 1: security context research
    stage1_out: Stage1Output | None = None
    if 1 not in config.skip_stages:
        stage1_out = await run_stage1(config, checkpoint)

    # Pause for user review before continuing (skip when resuming a completed stage 1)
    stage1_was_cached = config.resume and checkpoint.is_complete("stage1")
    if not stage1_was_cached and 1 not in config.skip_stages and not all(s in config.skip_stages for s in range(2, 5)):
        details_dir_preview = os.path.join(config.output_dir, "stage-1-details")
        logger.info(
            "Stage 1 complete. Review generated files in: %s", details_dir_preview
        )
        input("\nPress Enter to continue to the next stages...")

    # Resolve directive paths (from stage1 output or default locations)
    details_dir = os.path.join(config.output_dir, "stage-1-details")
    auditing_focus_path = (
        stage1_out.auditing_focus_path if stage1_out
        else os.path.join(details_dir, "auditing-focus.md")
    )
    vuln_criteria_path = (
        stage1_out.vuln_criteria_path if stage1_out
        else os.path.join(details_dir, "vulnerability-criteria.md")
    )

    # Stage 2: decompose project into analysis units
    analysis_units: list[AnalysisUnit] = []
    if 2 not in config.skip_stages:
        analysis_units = await run_stage2(config, checkpoint, auditing_focus_path)
    else:
        logger.info("Stage 2 skipped. Loading existing analysis units.")
        stage2_dir = os.path.join(config.output_dir, "stage-2-details")
        analysis_units = parse_au_files(stage2_dir)

    if not analysis_units and 3 not in config.skip_stages:
        raise RuntimeError("Stage 2 produced no analysis units.")

    # Stage 3: bug discovery per AU
    bug_files: list[str] = []
    if 3 not in config.skip_stages:
        bug_files = await run_stage3(
            analysis_units, config, checkpoint,
            auditing_focus_path, vuln_criteria_path,
        )
    else:
        logger.info("Stage 3 skipped.")
        bug_files = list_json_files(os.path.join(config.output_dir, "stage-3-details"))

    # Stage 4: evaluate findings
    if 4 not in config.skip_stages:
        await run_stage4(bug_files, config, checkpoint, vuln_criteria_path)
    else:
        logger.info("Stage 4 skipped.")

    logger.info("Audit complete.")
