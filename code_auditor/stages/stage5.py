from __future__ import annotations

import json
import os
import shutil

from ..agent import run_agent
from ..checkpoint import CheckpointManager
from ..config import AuditConfig, select_poc_model
from ..logger import get_logger
from ..poc_artifacts import ASAN_REPORT_FILENAME, TRIGGER_GRAPH_FILENAME
from ..prompts import load_prompt
from ..repos import capture_repo_identity
from ..reproduction_status import is_failed_status, read_reproduction_status
from ..retention import (
    RetentionError,
    export_retained_artifacts,
    secure_generated_manifest_mode,
)
from ..sandbox import DockerScratch
from ..utils import format_validation_issues, record_task_error, run_parallel_limited
from ..validation.stage5 import validate_stage5_trigger_graph
from ..wiki import build_wiki_context

logger = get_logger("stage5")

# Stage 5 agents need generous turn budgets — PoC development involves
# building projects, writing exploit code, running/debugging, and iterating.
_MAX_TURNS = 500
_DEFAULT_EFFORT = "medium"


def _task_key(vuln_id: str) -> str:
    return f"stage5:{vuln_id}"


def _is_fp_report(report_path: str | None) -> bool:
    return report_path is not None and os.path.basename(os.path.dirname(report_path)).endswith("_fp")


def _read_vuln_id(file_path: str) -> str | None:
    try:
        with open(file_path) as f:
            data = json.load(f)
        return data.get("id")
    except Exception as e:
        logger.warning("Failed to read vuln id from %s: %s", file_path, e)
        return None


def _resolve_reproduction_report(poc_dir: str) -> str | None:
    """Return the Stage 5 report path, normalizing failed reports to ``_fp``.

    Agents are instructed to rename failed reproductions to ``*_fp``, but older
    output and interrupted runs may leave a false-positive report in the normal
    PoC directory. Normalize that shape so Stage 6 cannot treat it as a
    reproduced vulnerability.
    """
    report_path = os.path.join(poc_dir, "report.md")
    fp_dir = poc_dir + "_fp"
    fp_report_path = os.path.join(fp_dir, "report.md")

    if os.path.exists(report_path):
        status = read_reproduction_status(report_path)
        if is_failed_status(status):
            if os.path.isdir(fp_dir):
                logger.warning(
                    "Stage 5: Failed report found in %s, but %s already exists. Using existing _fp report.",
                    poc_dir,
                    fp_dir,
                )
                return fp_report_path if os.path.exists(fp_report_path) else None

            shutil.move(poc_dir, fp_dir)
            logger.info("Stage 5: Normalized failed reproduction output to %s.", fp_dir)
            return fp_report_path if os.path.exists(fp_report_path) else None

        return report_path

    if os.path.exists(fp_report_path):
        return fp_report_path

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
    persistent_poc_dir = os.path.join(config.output_dir, "stage5-pocs", vuln_id)

    if checkpoint.is_complete(key):
        logger.info("Stage 5: %s already complete, skipping.", vuln_id)
        resolved = _resolve_reproduction_report(persistent_poc_dir)
        if _is_fp_report(resolved):
            logger.info("Stage 5: %s marked as false positive.", vuln_id)
            return None
        return resolved

    logger.info("Stage 5: Starting PoC reproduction for %s.", vuln_id)
    sandbox: DockerScratch | None = None
    work_config = config
    work_vuln_file = vuln_file_path
    if config.sandbox_enabled:
        identity = capture_repo_identity(config.target)
        source_commit = config.poc_source_commit or identity.get("commit") or ""
        sandbox = DockerScratch(config, f"stage5-{vuln_id}")
        try:
            await sandbox.prepare(config.target, source_commit)
            work_config = sandbox.audit_config(config)
            work_vuln_file = str(
                sandbox.copy_input(vuln_file_path, "finding.json")
            )
        except Exception:
            await sandbox.close()
            raise

    poc_target = work_config.poc_worktree or work_config.target
    poc_dir = os.path.join(work_config.output_dir, "stage5-pocs", vuln_id)
    os.makedirs(poc_dir, exist_ok=True)

    prompt = load_prompt("stage5.md", {
        "finding_file_path": work_vuln_file,
        "target_path": poc_target,
        "poc_dir": poc_dir,
        "finding_id": vuln_id,
        "wiki_context": build_wiki_context(config, stage=5),
    })

    log_file = os.path.join(poc_dir, "agent.log")
    resolved_report: str | None = None
    reproduced = False
    task_error: BaseException | None = None
    try:
        await run_agent(
            prompt,
            work_config,
            cwd=poc_target,
            max_turns=_MAX_TURNS,
            model=select_poc_model(config),
            effort=_DEFAULT_EFFORT,
            log_file=log_file,
            sandbox=sandbox,
        )

        resolved_report = _resolve_reproduction_report(poc_dir)
        reproduced = bool(
            resolved_report
            and read_reproduction_status(resolved_report) == "reproduced"
        )
        if reproduced and resolved_report is not None:
            resolved_poc_dir = os.path.dirname(resolved_report)
            issues = validate_stage5_trigger_graph(resolved_poc_dir, vuln_id)
            if issues:
                graph_path = os.path.join(resolved_poc_dir, TRIGGER_GRAPH_FILENAME)
                logger.warning(
                    "Stage 5: Trigger graph validation failed for %s\n%s",
                    vuln_id,
                    format_validation_issues(issues),
                )
                repair_prompt = (
                    f"The Stage 5 trigger graph at `{graph_path}` is missing or invalid. "
                    "Create or repair it using only the call path verified while running "
                    "the PoC. Do not invent stack frames, parameter values, sanitizer "
                    "output, or runtime evidence. Fix every issue below:\n\n"
                    f"```\n{format_validation_issues(issues)}\n```"
                )
                await run_agent(
                    repair_prompt,
                    work_config,
                    cwd=poc_target,
                    max_turns=15,
                    model=select_poc_model(config),
                    effort=_DEFAULT_EFFORT,
                    log_file=log_file,
                    sandbox=sandbox,
                )
                issues = validate_stage5_trigger_graph(resolved_poc_dir, vuln_id)
                if issues:
                    logger.warning(
                        "Stage 5: Trigger graph remains unavailable for %s\n%s",
                        vuln_id,
                        format_validation_issues(issues),
                    )

        if sandbox is not None:
            if resolved_report is None:
                raise RuntimeError(
                    f"Stage 5 did not produce report.md for {vuln_id}"
                )
            retained_source = os.path.dirname(resolved_report)
            persistent_destination = persistent_poc_dir
            if os.path.basename(retained_source).endswith("_fp"):
                persistent_destination += "_fp"
            secure_generated_manifest_mode(retained_source)
            try:
                manifest = export_retained_artifacts(
                    retained_source,
                    persistent_destination,
                    required_paths=("report.md", "reproduce.sh"),
                    max_file_bytes=config.retain_max_file_bytes,
                    max_total_bytes=config.retain_max_total_bytes,
                )
            except RetentionError as exc:
                manifest_path = os.path.join(
                    retained_source, "retain-manifest.json"
                )
                logger.warning(
                    "Stage 5: Retain manifest validation failed for %s: %s. "
                    "Requesting one bounded repair.",
                    vuln_id,
                    exc,
                )
                repair_prompt = (
                    f"The Stage 5 retain manifest at `{manifest_path}` was rejected: "
                    f"{exc}. Repair only `retain-manifest.json` so it exactly follows "
                    "the schema in the Stage 5 instructions and lists the existing, "
                    "small files needed for independent reproduction and review. "
                    "It must include `reproduce.sh` with role `entrypoint` and "
                    "`report.md` with role `report`; do not list the manifest itself, "
                    "agent.log, build trees, caches, source checkouts, binaries, or "
                    "other disposable files. Do not alter the reproduction result or "
                    "create any new runtime evidence."
                )
                await run_agent(
                    repair_prompt,
                    work_config,
                    cwd=poc_target,
                    max_turns=15,
                    model=select_poc_model(config),
                    effort=_DEFAULT_EFFORT,
                    log_file=log_file,
                    sandbox=sandbox,
                )
                secure_generated_manifest_mode(retained_source)
                manifest = export_retained_artifacts(
                    retained_source,
                    persistent_destination,
                    required_paths=("report.md", "reproduce.sh"),
                    max_file_bytes=config.retain_max_file_bytes,
                    max_total_bytes=config.retain_max_total_bytes,
                )
            logger.info(
                "Stage 5: Exported %d retained files (%d bytes) for %s.",
                len(manifest.files),
                manifest.total_bytes,
                vuln_id,
            )
            resolved_report = os.path.join(persistent_destination, "report.md")

    except BaseException as exc:
        # Keep the actual PoC/agent failure as the task result.  Cleanup is
        # best-effort and must not replace it with a teardown error.
        task_error = exc
        raise

    finally:
        if sandbox is not None:
            try:
                await sandbox.close()
            except Exception:
                if task_error is None:
                    raise
                logger.exception(
                    "Stage 5: failed to clean up scratch workspace for %s; "
                    "preserving the original task error.",
                    vuln_id,
                )

    checkpoint.mark_complete(key)
    if _is_fp_report(resolved_report):
        logger.info("Stage 5: %s marked as false positive.", vuln_id)
        return None

    has_report = resolved_report is not None
    has_graph = bool(
        reproduced
        and resolved_report
        and not validate_stage5_trigger_graph(
            os.path.dirname(resolved_report), vuln_id
        )
    )
    has_asan = bool(
        resolved_report
        and os.path.isfile(
            os.path.join(os.path.dirname(resolved_report), ASAN_REPORT_FILENAME)
        )
    )
    logger.info(
        "Stage 5: %s complete (report=%s, graph=%s, asan=%s)",
        vuln_id,
        has_report,
        has_graph,
        has_asan,
    )
    return resolved_report


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
            record_task_error(
                config,
                "stage5",
                os.path.splitext(os.path.basename(vuln_files[i]))[0],
                error,
            )
            continue
        if value:
            reports.append(value)

    logger.info("Stage 5 complete. %d reports generated (from %d vulnerabilities).", len(reports), len(vuln_files))
    return reports
