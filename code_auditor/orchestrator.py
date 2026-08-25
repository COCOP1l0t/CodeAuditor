from __future__ import annotations

import os

from .checkpoint import CheckpointManager
from .config import AnalysisUnit, AuditConfig
from .logger import get_logger
from .repos import ensure_poc_worktree
from .stages.stage0 import run_setup
from .stages.stage1 import Stage1Output, run_stage1
from .stages.stage2 import run_stage2
from .stages.stage3 import run_stage3
from .stages.stage4 import run_stage4
from .stages.stage5 import run_stage5
from .stages.stage6 import run_stage6
from .tui import TUIManager

logger = get_logger("orchestrator")


async def run_audit(config: AuditConfig, tui: TUIManager | None = None) -> None:
    checkpoint = CheckpointManager(config.output_dir, config.resume)

    if config.resume:
        logger.info("Resume mode enabled. Existing output files and markers will be reused.")

    # Stage 0: setup
    if tui:
        tui.begin_stage(0, "Setting up output directory")
    await run_setup(config)
    if tui:
        tui.end_stage(0)

    # Stage 1: security context research
    stage1_out: Stage1Output | None = None
    if tui:
        tui.begin_stage(1, "Researching security context")
    stage1_out = await run_stage1(config, checkpoint)
    if tui:
        tui.end_stage(1)

    # Resolve directive paths (from stage1 output or default locations)
    details_dir = os.path.join(config.output_dir, "stage1-security-context")
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
    if tui:
        tui.begin_stage(2, "Decomposing codebase")
    analysis_units = await run_stage2(config, checkpoint, auditing_focus_path)
    if tui:
        tui.stage_progress(2, items_done=len(analysis_units), items_total=len(analysis_units),
                           detail=f"{len(analysis_units)} analysis units found")
        tui.end_stage(2)

    if not analysis_units:
        raise RuntimeError("Stage 2 produced no analysis units.")

    # Stage 3: bug discovery per AU
    bug_files: list[str] = []
    total_aus = len(analysis_units)
    if tui:
        tui.begin_stage(3, f"Discovering bugs across {total_aus} AUs")

    bug_files = await run_stage3(
        analysis_units, config, checkpoint,
        auditing_focus_path, vuln_criteria_path,
    )
    if tui:
        tui.stage_progress(3, items_done=total_aus, items_total=total_aus,
                           detail=f"{len(bug_files)} findings")
        tui.end_stage(3)

    # Stage 4: evaluate findings
    vuln_files: list[str] = []
    if tui:
        tui.begin_stage(4, f"Evaluating {len(bug_files)} findings")
    vuln_files = await run_stage4(bug_files, config, checkpoint, vuln_criteria_path)
    if tui:
        tui.stage_progress(4, items_done=len(vuln_files), items_total=len(bug_files),
                           detail=f"{len(vuln_files)} confirmed vulnerabilities")
        tui.end_stage(4)

    # Stage 5: PoC reproduction per verified vulnerability
    stage5_reports: list[str] = []
    if tui:
        tui.begin_stage(5, f"Reproducing {len(vuln_files)} vulnerabilities")
    if vuln_files and not config.sandbox_enabled and config.poc_worktree is None:
        config.poc_worktree = await ensure_poc_worktree(config.target, config.output_dir)
    stage5_reports = await run_stage5(vuln_files, config, checkpoint)
    if tui:
        tui.stage_progress(5, items_done=len(stage5_reports), items_total=len(vuln_files),
                           detail=f"{len(stage5_reports)} PoCs reproduced")
        tui.end_stage(5)

    # Stage 6: disclosure preparation per reproduced vulnerability
    if tui:
        tui.begin_stage(6, f"Preparing {len(stage5_reports)} disclosures")
    await run_stage6(stage5_reports, config, checkpoint)
    if tui:
        tui.end_stage(6)

    if config.task_errors:
        logger.error(
            "Audit finished with %d failed agent task(s): %s",
            len(config.task_errors),
            "; ".join(config.task_errors),
        )
    logger.info("Audit complete.")
