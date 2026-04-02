from __future__ import annotations

import os

from ..checkpoint import CheckpointManager
from ..config import AuditConfig
from ..logger import get_logger
from ..report.generate import generate_report

logger = get_logger("stage5")
_TASK_KEY = "stage5"


async def run_stage5(config: AuditConfig, checkpoint: CheckpointManager) -> str:
    report_path = os.path.join(config.output_dir, "report.md")

    if checkpoint.is_complete(_TASK_KEY):
        logger.info("Stage 5 already complete.")
        return report_path

    research_record = os.path.join(config.output_dir, "stage-1-details", "stage-1-security-context.json")
    stage4_dir = os.path.join(config.output_dir, "stage-4-details")
    summary = generate_report(research_record, stage4_dir, report_path)

    stat = os.stat(report_path)
    if stat.st_size == 0:
        raise RuntimeError(f"Report file missing or empty: {report_path}")

    checkpoint.mark_complete(_TASK_KEY)
    logger.info("Stage 5 complete. Report: %s", report_path)
    logger.info("Report summary: total=%s severities=%s", summary.total_findings, summary.severity_counts)
    return report_path
