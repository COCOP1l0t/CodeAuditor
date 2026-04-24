from __future__ import annotations

import asyncio
import os
from pathlib import Path

from ..agent import run_agent
from ..checkpoint import CheckpointManager
from ..config import AuditConfig
from ..logger import get_logger
from ..prompts import load_prompt
from ..utils import format_validation_issues, run_parallel_limited
from ..validation.stage6 import validate_stage6_verdict

logger = get_logger("stage6")

_MAX_TURNS = 200
_CHECK_TIMEOUT = 15 * 60  # 15 minutes

# Stage 6 may need to consult upstream / third-party documentation on the web
# in addition to in-repo docs, so it gets WebFetch / WebSearch on top of the
# default tools.
_ALLOWED_TOOLS = ["Read", "Glob", "Grep", "Write", "Edit", "Bash", "WebFetch", "WebSearch"]


def _task_key(vuln_id: str) -> str:
    return f"stage6:{vuln_id}"


def _vuln_id_from_report(report_path: str) -> str | None:
    """Extract the vuln id from a stage5 report path .../stage5-pocs/{id}/report.md.

    Returns None for ``_fp``-suffixed directories (failed reproduction) — those
    should be skipped by Stage 6.
    """
    parent = Path(report_path).parent
    name = parent.name
    if name.endswith("_fp"):
        return None
    return name


def _find_finding_file(vuln_id: str, output_dir: str) -> str | None:
    path = os.path.join(output_dir, "stage4-vulnerabilities", f"{vuln_id}.json")
    return path if os.path.exists(path) else None


def _filter_reproduced(stage5_reports: list[str]) -> list[str]:
    """Keep only Stage 5 reports from successful reproductions (no ``_fp`` suffix)."""
    return [r for r in stage5_reports if not Path(r).parent.name.endswith("_fp")]


async def _run_check(
    report_path: str,
    config: AuditConfig,
    checkpoint: CheckpointManager,
) -> str | None:
    """Run the API-misuse check on one reproduced PoC.

    Returns the original ``report_path`` if the PoC was classified as a real
    vulnerability or uncertain (i.e. should proceed to disclosure), or
    ``None`` if it was classified as API misuse.
    """
    vuln_id = _vuln_id_from_report(report_path)
    if not vuln_id:
        logger.warning("Stage 6: Cannot extract vuln id from %s, skipping.", report_path)
        return None

    key = _task_key(vuln_id)
    verdict_root = os.path.join(config.output_dir, "stage6-api-check")
    real_dir = os.path.join(verdict_root, vuln_id)
    misuse_dir = os.path.join(verdict_root, f"{vuln_id}_misuse")

    if checkpoint.is_complete(key):
        if os.path.isdir(misuse_dir):
            logger.info("Stage 6: %s already complete (api-misuse), skipping disclosure.", vuln_id)
            return None
        if os.path.isdir(real_dir):
            logger.info("Stage 6: %s already complete (real/uncertain), will proceed to disclosure.", vuln_id)
            return report_path
        logger.warning(
            "Stage 6: %s marked complete but no verdict dir found — passing through to disclosure.",
            vuln_id,
        )
        return report_path

    logger.info("Stage 6: Checking %s for API misuse.", vuln_id)
    os.makedirs(verdict_root, exist_ok=True)

    poc_dir = str(Path(report_path).parent)
    finding_file = _find_finding_file(vuln_id, config.output_dir)
    if finding_file:
        finding_reference = (
            "The evaluated finding with data-flow trace, CWE, and CVSS analysis is at:\n\n"
            f"`{finding_file}`\n\n"
            "Read this file for additional context on the vulnerability."
        )
    else:
        finding_reference = (
            "No evaluated finding file is available; use the Stage 5 report for context."
        )

    prompt = load_prompt("stage6.md", {
        "vuln_report_path": report_path,
        "poc_dir": poc_dir,
        "finding_reference": finding_reference,
        "target_path": config.target,
        "verdict_dir": verdict_root,
        "vuln_id": vuln_id,
    })

    log_file = os.path.join(verdict_root, "logs", f"{vuln_id}.log")

    timed_out = False
    task = asyncio.create_task(
        run_agent(
            prompt,
            config,
            cwd=config.target,
            allowed_tools=_ALLOWED_TOOLS,
            max_turns=_MAX_TURNS,
            log_file=log_file,
        )
    )
    done, _ = await asyncio.wait({task}, timeout=_CHECK_TIMEOUT)

    if not done:
        timed_out = True
        task.cancel()
        grace_done, _ = await asyncio.wait({task}, timeout=30)
        if not grace_done:
            logger.warning("Stage 6: %s agent did not exit after cancel, moving on.", vuln_id)
        logger.warning(
            "Stage 6: %s timed out after %d minutes — defaulting to real-vulnerability.",
            vuln_id, _CHECK_TIMEOUT // 60,
        )
    else:
        exc = task.exception()
        if exc is not None:
            raise exc

    checkpoint.mark_complete(key)

    # Agent produced an api-misuse verdict.
    if os.path.isdir(misuse_dir):
        verdict_file = os.path.join(misuse_dir, "verdict.md")
        vissues = validate_stage6_verdict(verdict_file)
        if vissues:
            logger.warning(
                "Stage 6: %s misuse verdict validation failed:\n%s",
                vuln_id, format_validation_issues(vissues),
            )
        logger.info("Stage 6: %s classified as api-misuse.", vuln_id)
        return None

    # Agent produced a real-vulnerability or uncertain verdict.
    if os.path.isdir(real_dir):
        verdict_file = os.path.join(real_dir, "verdict.md")
        vissues = validate_stage6_verdict(verdict_file)
        if vissues:
            logger.warning(
                "Stage 6: %s verdict validation failed:\n%s",
                vuln_id, format_validation_issues(vissues),
            )
        logger.info("Stage 6: %s classified as real-vulnerability or uncertain.", vuln_id)
        return report_path

    # Agent produced no verdict directory (timeout or other failure) —
    # default to pass-through so a real bug is not silently dropped.
    if timed_out:
        os.makedirs(real_dir, exist_ok=True)
        with open(os.path.join(real_dir, "verdict.md"), "w") as f:
            f.write(
                f"# Verdict: {vuln_id}\n\n"
                "## Verdict\n\nuncertain\n\n"
                "## Summary\n\n"
                f"API-misuse check timed out after {_CHECK_TIMEOUT // 60} minutes; "
                "defaulting to `uncertain` so the finding proceeds to disclosure.\n\n"
                "## PoC Behavior\n\n(Not analyzed — check timed out.)\n\n"
                "## Documentation References\n\n(Not collected — check timed out.)\n\n"
                "## Analysis\n\n(Not performed — check timed out.)\n\n"
                "## Justification\n\n"
                "Pass-through default applies because the check did not complete.\n"
            )
    logger.warning(
        "Stage 6: %s produced no verdict directory — passing through to disclosure.",
        vuln_id,
    )
    return report_path


async def run_stage6(
    stage5_reports: list[str],
    config: AuditConfig,
    checkpoint: CheckpointManager,
) -> list[str]:
    """Check each reproduced PoC for API misuse in parallel.

    Returns the subset of input reports that were NOT classified as API misuse
    (i.e. should continue to Stage 7 disclosure).
    """
    reproduced = _filter_reproduced(stage5_reports)
    if not reproduced:
        logger.info("Stage 6: No reproduced PoCs to check.")
        return []

    logger.info("Stage 6: Checking %d reproduced PoCs for API misuse.", len(reproduced))

    results = await run_parallel_limited(
        reproduced,
        config.max_parallel,
        lambda report, _: _run_check(report, config, checkpoint),
    )

    cleared: list[str] = []
    for i, (status, value, error) in enumerate(results):
        if i >= len(reproduced):
            continue
        if status == "rejected":
            vuln_id = Path(reproduced[i]).parent.name
            logger.error("Stage 6: %s failed: %s — passing through to disclosure.", vuln_id, error)
            cleared.append(reproduced[i])
            continue
        if value:
            cleared.append(value)

    logger.info(
        "Stage 6 complete. %d of %d PoCs cleared the API-misuse check.",
        len(cleared), len(reproduced),
    )
    return cleared
