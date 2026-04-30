from __future__ import annotations

import json
import os
import re
import shutil

from ..agent import run_agent
from ..checkpoint import CheckpointManager
from ..config import AuditConfig
from ..logger import get_logger
from ..prompts import load_prompt
from ..utils import (
    format_validation_issues,
    list_json_files,
    run_parallel_limited,
)
from ..validation.stage4 import validate_stage4_file
from ..wiki import build_wiki_context

logger = get_logger("stage4")

_SEVERITY_ORDER = ["Critical", "High", "Medium", "Low"]
_SEVERITY_PREFIX = {"Critical": "C", "High": "H", "Medium": "M", "Low": "L"}


def _task_key(finding_filename: str) -> str:
    return f"stage4:{finding_filename}"


def _cvss_to_severity(cvss: float) -> str | None:
    """Derive severity from CVSS v3.1 base score."""
    if cvss >= 9.0:
        return "Critical"
    if cvss >= 7.0:
        return "High"
    if cvss >= 4.0:
        return "Medium"
    if cvss >= 0.1:
        return "Low"
    return None


def _read_severity_and_cvss(file_path: str) -> tuple[str | None, float]:
    try:
        with open(file_path) as f:
            data = json.load(f)
        try:
            cvss = float(data.get("cvss_score", 0))
        except (TypeError, ValueError):
            cvss = 0.0
        severity = _cvss_to_severity(cvss)
        return severity, cvss
    except Exception as e:
        logger.warning("Failed to read severity from %s: %s", file_path, e)
        return None, 0.0


def _read_existing_id(file_path: str) -> str | None:
    try:
        with open(file_path) as f:
            data = json.load(f)
        return data.get("id")
    except Exception:
        return None


def _inject_id_and_severity(file_path: str, real_id: str, severity: str) -> None:
    with open(file_path) as f:
        data = json.load(f)
    data["id"] = real_id
    data["severity"] = severity
    with open(file_path, "w") as f:
        json.dump(data, f, indent=2)


def _list_existing_final_files(stage4_dir: str) -> list[str]:
    files = list_json_files(stage4_dir)
    return [f for f in files if os.path.basename(f) != "_pending"]


async def _run_finding(
    stage3_file_path: str,
    config: AuditConfig,
    checkpoint: CheckpointManager,
    vuln_criteria_path: str,
) -> str | None:
    stage3_filename = os.path.basename(stage3_file_path)
    key = _task_key(stage3_filename)
    pending_dir = os.path.join(config.output_dir, "stage4-vulnerabilities", "_pending")
    pending_path = os.path.join(pending_dir, stage3_filename)
    log_file = os.path.join(
        config.output_dir, "stage4-vulnerabilities", "logs",
        f"{os.path.splitext(stage3_filename)[0]}.log",
    )

    if checkpoint.is_complete(key):
        logger.info("Stage 4: %s already complete, skipping.", stage3_filename)
        return pending_path if os.path.exists(pending_path) else None

    logger.info("Stage 4: Starting evaluation of %s.", stage3_filename)
    prompt = load_prompt("stage4.md", {
        "finding_file_path": stage3_file_path,
        "output_path": pending_path,
        "vuln_criteria_path": vuln_criteria_path,
        "wiki_context": build_wiki_context(config, stage=4),
    })

    await run_agent(prompt, config, cwd=config.target, max_turns=100, log_file=log_file)

    confirmed = os.path.exists(pending_path)
    if confirmed:
        issues = validate_stage4_file(pending_path)
        if issues:
            logger.warning("Stage 4: Validation failed for %s\n%s", pending_path, format_validation_issues(issues))
            repair_prompt = (
                f"The evaluation file at `{pending_path}` failed validation. "
                f"Please fix all issues below:\n\n```\n{format_validation_issues(issues)}\n```"
            )
            await run_agent(repair_prompt, config, cwd=config.target, max_turns=10, log_file=log_file)
            issues = validate_stage4_file(pending_path)
            if issues:
                logger.warning("Stage 4: Repair failed for %s\n%s", pending_path, format_validation_issues(issues))

    checkpoint.mark_complete(key)
    logger.info("Stage 4: %s complete (confirmed=%s)", stage3_filename, confirmed)
    return pending_path if confirmed else None


def _assign_ids_and_finalize(pending_paths: list[str], config: AuditConfig) -> list[str]:
    stage4_dir = os.path.join(config.output_dir, "stage4-vulnerabilities")
    existing_final_files = _list_existing_final_files(stage4_dir)

    counters: dict[str, int] = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}

    for file_path in existing_final_files:
        existing_id = _read_existing_id(file_path)
        if not existing_id or "-" not in existing_id:
            continue
        prefix, number_text = existing_id.split("-", 1)
        for sev, sev_prefix in _SEVERITY_PREFIX.items():
            if sev_prefix == prefix:
                counters[sev] = max(counters[sev], int(number_text))
                break

    findings: list[tuple[str, str, float]] = []  # (pending_path, severity, cvss)
    for pending_path in pending_paths:
        severity, cvss = _read_severity_and_cvss(pending_path)
        if severity:
            findings.append((pending_path, severity, cvss))
        else:
            logger.warning("Stage 4: Skipping %s because severity could not be derived from CVSS score.", os.path.basename(pending_path))

    # Sort by severity order, then by cvss_score descending (higher score -> smaller ID)
    findings.sort(key=lambda x: (_SEVERITY_ORDER.index(x[1]), -x[2]))

    finalized: list[str] = list(existing_final_files)
    for pending_path, severity, _cvss in findings:
        next_count = counters[severity] + 1
        counters[severity] = next_count
        real_id = f"{_SEVERITY_PREFIX[severity]}-{next_count:02d}"
        final_path = os.path.join(stage4_dir, f"{real_id}.json")
        shutil.move(pending_path, final_path)
        _inject_id_and_severity(final_path, real_id, severity)
        finalized.append(final_path)
        logger.info("Stage 4: Assigned %s to %s", real_id, os.path.basename(pending_path))

    finalized.sort(key=lambda a: (
        {"C": 0, "H": 1, "M": 2, "L": 3}.get(os.path.basename(a).split("-")[0], 99),
        a,
    ))
    return finalized


def _backfill_stage4_markers(
    finding_files: list[str],
    config: AuditConfig,
    checkpoint: CheckpointManager,
) -> None:
    """Create markers for findings already processed in a previous run.

    When a previous run evaluated findings but was interrupted (or predates
    marker-based tracking), some findings may lack checkpoint markers even
    though they were already processed.

    Heuristic: find the highest AU number that has any file in ``_pending/``
    and create markers for every input finding whose AU number is <= that
    value, since those AUs must have been reached by the previous run.
    """
    pending_dir = os.path.join(config.output_dir, "stage4-vulnerabilities", "_pending")
    if not os.path.isdir(pending_dir):
        return

    pending_files = os.listdir(pending_dir)
    if not pending_files:
        return

    au_re = re.compile(r"AU-(\d+)")
    max_au = 0
    for name in pending_files:
        m = au_re.search(name)
        if m:
            max_au = max(max_au, int(m.group(1)))

    if max_au == 0:
        return

    backfilled = 0
    for ff in finding_files:
        filename = os.path.basename(ff)
        m = au_re.search(filename)
        if m and int(m.group(1)) <= max_au:
            key = _task_key(filename)
            if not checkpoint.is_complete(key):
                checkpoint.mark_complete(key)
                backfilled += 1

    if backfilled:
        logger.info(
            "Stage 4: Backfilled %d markers (highest completed AU: %d).",
            backfilled, max_au,
        )


async def run_stage4(
    finding_files: list[str],
    config: AuditConfig,
    checkpoint: CheckpointManager,
    vuln_criteria_path: str,
) -> list[str]:
    if not finding_files:
        logger.info("Stage 4: No findings to evaluate.")
        return _list_existing_final_files(os.path.join(config.output_dir, "stage4-vulnerabilities"))

    if config.resume:
        _backfill_stage4_markers(finding_files, config, checkpoint)

    results = await run_parallel_limited(
        finding_files,
        config.max_parallel,
        lambda ff, _: _run_finding(ff, config, checkpoint, vuln_criteria_path),
    )

    confirmed_pending: list[str] = []
    for i, (status, value, error) in enumerate(results):
        if i >= len(finding_files):
            continue
        if status == "rejected":
            logger.error("Stage 4: %s failed: %s", os.path.basename(finding_files[i]), error)
            continue
        if value:
            confirmed_pending.append(value)

    logger.info("Stage 4: %s confirmed findings (from %s candidates).", len(confirmed_pending), len(finding_files))

    final_paths = _assign_ids_and_finalize(confirmed_pending, config)
    logger.info("Stage 4 complete. Final findings: %s", len(final_paths))
    return final_paths
