from __future__ import annotations

import asyncio
import os
from pathlib import Path

from ..agent import run_agent
from ..checkpoint import CheckpointManager
from ..config import AuditConfig, select_poc_model
from ..logger import get_logger
from ..prompts import load_prompt
from ..utils import run_parallel_limited

logger = get_logger("stage6")

# Stage 6 agents verify reproduction, create minimal PoCs, and write
# polished disclosure artifacts — similar complexity to Stage 5.
_MAX_TURNS = 500
_DEFAULT_EFFORT = "medium"
_DISCLOSURE_TIMEOUT = 20 * 60  # 20 minutes


def _task_key(vuln_id: str) -> str:
    return f"stage6:{vuln_id}"


def _vuln_id_from_report(report_path: str) -> str | None:
    """Extract vulnerability ID from a stage 5 report path.

    Expects paths like .../stage5-pocs/{vuln_id}/report.md
    """
    parent = Path(report_path).parent
    name = parent.name
    if name.endswith("_fp"):
        return None
    return name


def _find_finding_file(vuln_id: str, output_dir: str) -> str | None:
    """Locate the stage 4 evaluated finding JSON for a vulnerability ID."""
    path = os.path.join(output_dir, "stage4-vulnerabilities", f"{vuln_id}.json")
    return path if os.path.exists(path) else None


def _filter_reproduced(stage5_reports: list[str]) -> list[str]:
    """Keep only stage 5 reports from successful reproductions (no _fp suffix)."""
    return [r for r in stage5_reports if not Path(r).parent.name.endswith("_fp")]


async def _run_disclosure(
    report_path: str,
    config: AuditConfig,
    checkpoint: CheckpointManager,
) -> str | None:
    """Prepare disclosure artifacts for a single reproduced vulnerability."""
    vuln_id = _vuln_id_from_report(report_path)
    if not vuln_id:
        logger.warning("Stage 6: Cannot extract vuln ID from %s, skipping.", report_path)
        return None

    key = _task_key(vuln_id)
    stage6_vuln_dir = os.path.join(config.output_dir, "stage6-disclosures", vuln_id)
    disclosure_dir = os.path.join(stage6_vuln_dir, "disclosure")
    disclosure_report = os.path.join(disclosure_dir, "report.md")

    if checkpoint.is_complete(key):
        logger.info("Stage 6: %s already complete, skipping.", vuln_id)
        return disclosure_report if os.path.exists(disclosure_report) else None

    logger.info("Stage 6: Starting disclosure preparation for %s.", vuln_id)
    os.makedirs(disclosure_dir, exist_ok=True)

    # Locate inputs
    poc_dir = str(Path(report_path).parent)
    finding_file = _find_finding_file(vuln_id, config.output_dir)

    if finding_file:
        finding_reference = (
            "The evaluated finding with detailed data-flow trace, CWE, "
            "and CVSS analysis is at:\n\n"
            f"`{finding_file}`\n\n"
            "Read this file for additional context on the vulnerability."
        )
    else:
        finding_reference = (
            "No evaluated finding file is available. "
            "Use the vulnerability report for all details."
        )

    prompt = load_prompt("stage6.md", {
        "vuln_report_path": report_path,
        "poc_dir": poc_dir,
        "finding_reference": finding_reference,
        "target_path": config.target,
        "disclosure_dir": disclosure_dir,
        "vuln_id": vuln_id,
    })

    log_file = os.path.join(stage6_vuln_dir, "agent.log")

    timed_out = False
    task = asyncio.create_task(
        run_agent(
            prompt,
            config,
            cwd=config.target,
            max_turns=_MAX_TURNS,
            model=select_poc_model(config),
            effort=_DEFAULT_EFFORT,
            log_file=log_file,
        )
    )
    done, _ = await asyncio.wait({task}, timeout=_DISCLOSURE_TIMEOUT)

    if not done:
        timed_out = True
        task.cancel()
        grace_done, _ = await asyncio.wait({task}, timeout=30)
        if not grace_done:
            logger.warning("Stage 6: %s agent task did not exit after cancel, moving on.", vuln_id)
        logger.warning(
            "Stage 6: %s timed out after %d minutes.",
            vuln_id, _DISCLOSURE_TIMEOUT // 60,
        )
    else:
        exc = task.exception()
        if exc is not None:
            raise exc

    checkpoint.mark_complete(key)

    has_report = os.path.exists(disclosure_report)
    logger.info("Stage 6: %s complete (report=%s, timed_out=%s)", vuln_id, has_report, timed_out)
    return disclosure_report if has_report else None


async def run_stage6(
    stage5_reports: list[str],
    config: AuditConfig,
    checkpoint: CheckpointManager,
) -> list[str]:
    """Prepare disclosure artifacts for each reproduced vulnerability in parallel."""
    reproduced = _filter_reproduced(stage5_reports)
    if not reproduced:
        logger.info("Stage 6: No reproduced vulnerabilities to prepare disclosures for.")
        return []

    logger.info("Stage 6: Preparing disclosures for %d reproduced vulnerabilities.", len(reproduced))

    results = await run_parallel_limited(
        reproduced,
        config.max_parallel,
        lambda report, _: _run_disclosure(report, config, checkpoint),
    )

    disclosure_reports: list[str] = []
    for i, (status, value, error) in enumerate(results):
        if i >= len(reproduced):
            continue
        if status == "rejected":
            logger.error("Stage 6: %s failed: %s", os.path.basename(reproduced[i]), error)
            continue
        if value:
            disclosure_reports.append(value)

    logger.info(
        "Stage 6 complete. %d disclosure packages prepared (from %d reproduced vulnerabilities).",
        len(disclosure_reports), len(reproduced),
    )
    return disclosure_reports
