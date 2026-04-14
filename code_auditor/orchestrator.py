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
from .stages.stage5 import run_stage5
from .stages.stage6 import run_stage6
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
    if 2 not in config.skip_stages:
        analysis_units = await run_stage2(config, checkpoint, auditing_focus_path)
    else:
        logger.info("Stage 2 skipped. Loading existing analysis units.")
        stage2_dir = os.path.join(config.output_dir, "stage2-analysis-units")
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
        bug_files = list_json_files(os.path.join(config.output_dir, "stage3-findings"))

    # Stage 4: evaluate findings
    vuln_files: list[str] = []
    if 4 not in config.skip_stages:
        vuln_files = await run_stage4(bug_files, config, checkpoint, vuln_criteria_path)
    else:
        logger.info("Stage 4 skipped.")
        stage4_dir = os.path.join(config.output_dir, "stage4-vulnerabilities")
        vuln_files = [f for f in list_json_files(stage4_dir) if "_pending" not in f]

    # Stage 5: PoC reproduction per verified vulnerability
    stage5_reports: list[str] = []
    if 5 not in config.skip_stages:
        stage5_reports = await run_stage5(vuln_files, config, checkpoint)
    else:
        logger.info("Stage 5 skipped. Loading existing reports.")
        stage5_dir = os.path.join(config.output_dir, "stage5-pocs")
        if os.path.isdir(stage5_dir):
            for name in sorted(os.listdir(stage5_dir)):
                entry = os.path.join(stage5_dir, name)
                if os.path.isdir(entry):
                    report = os.path.join(entry, "report.md")
                    if os.path.exists(report):
                        stage5_reports.append(report)

    # Stage 6: disclosure preparation per reproduced vulnerability
    if 6 not in config.skip_stages:
        await run_stage6(stage5_reports, config, checkpoint)
    else:
        logger.info("Stage 6 skipped.")

    logger.info("Audit complete.")
