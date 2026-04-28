from __future__ import annotations

import asyncio
import json
import os
import shutil

from ..agent import run_agent
from ..checkpoint import CheckpointManager
from ..config import AuditConfig, select_poc_model
from ..logger import get_logger
from ..prompts import load_prompt
from ..utils import run_parallel_limited

logger = get_logger("stage5")

# Stage 5 agents need generous turn budgets — PoC development involves
# building projects, writing exploit code, running/debugging, and iterating.
_MAX_TURNS = 500
_DEFAULT_EFFORT = "medium"
_POC_TIMEOUT = 20 * 60  # 20 minutes


def _task_key(vuln_id: str) -> str:
    return f"stage5:{vuln_id}"


def _read_vuln_id(file_path: str) -> str | None:
    try:
        with open(file_path) as f:
            data = json.load(f)
        return data.get("id")
    except Exception as e:
        logger.warning("Failed to read vuln id from %s: %s", file_path, e)
        return None


async def _run_reproduce(
    vuln_file_path: str,
    config: AuditConfig,
    checkpoint: CheckpointManager,
) -> str | None:
    """Reproduce a single verified vulnerability and develop a PoC."""
    vuln_id = _read_vuln_id(vuln_file_path)
    if not vuln_id:
        logger.warning("Stage 5: Cannot read vulnerability ID from %s, skipping.", vuln_file_path)
        return None

    key = _task_key(vuln_id)
    poc_dir = os.path.join(config.output_dir, "stage5-pocs", vuln_id)
    report_path = os.path.join(poc_dir, "report.md")

    fp_report_path = os.path.join(poc_dir + "_fp", "report.md")

    if checkpoint.is_complete(key):
        logger.info("Stage 5: %s already complete, skipping.", vuln_id)
        if os.path.exists(report_path):
            return report_path
        if os.path.exists(fp_report_path):
            return fp_report_path
        return None

    logger.info("Stage 5: Starting PoC reproduction for %s.", vuln_id)
    os.makedirs(poc_dir, exist_ok=True)

    prompt = load_prompt("stage5.md", {
        "finding_file_path": vuln_file_path,
        "target_path": config.target,
        "poc_dir": poc_dir,
        "finding_id": vuln_id,
    })

    log_file = os.path.join(poc_dir, "agent.log")

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
    done, _ = await asyncio.wait({task}, timeout=_POC_TIMEOUT)

    if not done:
        # Timed out — cancel and allow a short grace period for cleanup.
        timed_out = True
        task.cancel()
        grace_done, _ = await asyncio.wait({task}, timeout=30)
        if not grace_done:
            logger.warning("Stage 5: %s agent task did not exit after cancel, moving on.", vuln_id)
        logger.warning(
            "Stage 5: %s timed out after %d minutes — marking as false positive.",
            vuln_id, _POC_TIMEOUT // 60,
        )
    else:
        # Task completed — re-raise if it failed (but not for CancelledError).
        exc = task.exception()
        if exc is not None:
            raise exc

    checkpoint.mark_complete(key)

    # The agent renames the directory with a _fp suffix on failed reproduction.
    fp_dir = poc_dir + "_fp"

    if timed_out and not os.path.isdir(fp_dir):
        # Agent didn't get to mark it — do it ourselves.
        os.makedirs(fp_dir, exist_ok=True)
        with open(os.path.join(fp_dir, "report.md"), "w") as f:
            f.write(
                f"# {vuln_id} — False Positive (timeout)\n\n"
                f"PoC development did not produce a working exploit within "
                f"the {_POC_TIMEOUT // 60}-minute time limit. "
                f"Marking as false positive.\n"
            )
        # Preserve the agent log in the _fp directory before cleanup.
        if os.path.exists(log_file):
            shutil.copy2(log_file, os.path.join(fp_dir, "agent.log"))
        # Clean up the original poc_dir if it exists
        if os.path.isdir(poc_dir):
            shutil.rmtree(poc_dir)

    if os.path.isdir(fp_dir):
        fp_report = os.path.join(fp_dir, "report.md")
        logger.info("Stage 5: %s marked as false positive.", vuln_id)
        return fp_report if os.path.exists(fp_report) else None

    has_report = os.path.exists(report_path)
    logger.info("Stage 5: %s complete (report=%s)", vuln_id, has_report)
    return report_path if has_report else None


async def run_stage5(
    vuln_files: list[str],
    config: AuditConfig,
    checkpoint: CheckpointManager,
) -> list[str]:
    """Run PoC reproduction for each verified vulnerability in parallel."""
    if not vuln_files:
        logger.info("Stage 5: No verified vulnerabilities to reproduce.")
        return []

    logger.info("Stage 5: Reproducing %d verified vulnerabilities.", len(vuln_files))

    results = await run_parallel_limited(
        vuln_files,
        config.max_parallel,
        lambda vf, _: _run_reproduce(vf, config, checkpoint),
    )

    reports: list[str] = []
    for i, (status, value, error) in enumerate(results):
        if i >= len(vuln_files):
            continue
        if status == "rejected":
            logger.error("Stage 5: %s failed: %s", os.path.basename(vuln_files[i]), error)
            continue
        if value:
            reports.append(value)

    logger.info("Stage 5 complete. %d reports generated (from %d vulnerabilities).", len(reports), len(vuln_files))
    return reports
