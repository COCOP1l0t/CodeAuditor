from __future__ import annotations

import os

from .checkpoint import CheckpointManager
from .config import AnalysisUnit, AuditConfig
from .logger import get_logger
from .parsing.stage3 import parse_au_files
from .stages.stage0 import run_setup
from .stages.stage1 import Stage1Output, run_stage1
from .stages.stage2_deployments import Stage2Output, run_stage2_deployments
from .stages.stage3 import run_stage3
from .stages.stage4 import run_stage4
from .stages.stage5 import run_stage5
from .stages.stage6 import run_stage6
from .stages.stage7 import run_stage7
from .utils import list_json_files

logger = get_logger("orchestrator")


async def run_audit(config: AuditConfig) -> None:
    checkpoint = CheckpointManager(config.output_dir, config.resume)

    if config.resume:
        logger.info("Resume mode enabled. Existing output files and markers will be reused.")

    if 0 not in config.skip_stages:
        await run_setup(config)

    stage1_out: Stage1Output | None = None
    if 1 not in config.skip_stages:
        stage1_out = await run_stage1(config, checkpoint)

    details_dir = os.path.join(config.output_dir, "stage1-security-context")
    auditing_focus_path = (
        stage1_out.auditing_focus_path if stage1_out
        else os.path.join(details_dir, "auditing-focus.md")
    )
    vuln_criteria_path = (
        stage1_out.vuln_criteria_path if stage1_out
        else os.path.join(details_dir, "vulnerability-criteria.md")
    )

    stage2_out: Stage2Output | None = None
    if 2 not in config.skip_stages:
        stage2_out = await run_stage2_deployments(config, checkpoint, auditing_focus_path)

    deployments_dir = os.path.join(config.output_dir, "stage2-deployments")
    deployment_summary_path = (
        stage2_out.deployment_summary_path if stage2_out
        else os.path.join(deployments_dir, "deployment-summary.md")
    )
    deployment_manifest_path = (
        stage2_out.manifest_path if stage2_out
        else os.path.join(deployments_dir, "manifest.json")
    )

    analysis_units: list[AnalysisUnit] = []
    if 3 not in config.skip_stages:
        analysis_units = await run_stage3(config, checkpoint, auditing_focus_path)
    else:
        logger.info("Stage 3 skipped. Loading existing analysis units.")
        stage3_dir = os.path.join(config.output_dir, "stage3-analysis-units")
        analysis_units = parse_au_files(stage3_dir)

    if not analysis_units and 4 not in config.skip_stages:
        raise RuntimeError("Stage 3 produced no analysis units.")

    bug_files: list[str] = []
    if 4 not in config.skip_stages:
        bug_files = await run_stage4(
            analysis_units, config, checkpoint,
            auditing_focus_path, vuln_criteria_path,
        )
    else:
        logger.info("Stage 4 skipped.")
        bug_files = list_json_files(os.path.join(config.output_dir, "stage4-findings"))

    vuln_files: list[str] = []
    if 5 not in config.skip_stages:
        vuln_files = await run_stage5(bug_files, config, checkpoint, vuln_criteria_path)
    else:
        logger.info("Stage 5 skipped.")
        stage5_dir = os.path.join(config.output_dir, "stage5-vulnerabilities")
        vuln_files = [f for f in list_json_files(stage5_dir) if "_pending" not in f]

    stage6_reports: list[str] = []
    if 6 not in config.skip_stages:
        stage6_reports = await run_stage6(vuln_files, config, checkpoint)
    else:
        logger.info("Stage 6 skipped. Loading existing reports.")
        stage6_dir = os.path.join(config.output_dir, "stage6-pocs")
        if os.path.isdir(stage6_dir):
            for name in sorted(os.listdir(stage6_dir)):
                entry = os.path.join(stage6_dir, name)
                if os.path.isdir(entry):
                    report = os.path.join(entry, "report.md")
                    if os.path.exists(report):
                        stage6_reports.append(report)

    if 7 not in config.skip_stages:
        await run_stage7(stage6_reports, config, checkpoint)
    else:
        logger.info("Stage 7 skipped.")

    logger.info("Audit complete.")
