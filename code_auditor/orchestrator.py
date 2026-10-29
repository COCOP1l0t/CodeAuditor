from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Protocol
from uuid import uuid4

from .checkpoint import CheckpointManager
from .config import AuditConfig, resolve_agent_model
from .layout import stage1_paths
from .logger import get_logger
from .repos import cleanup_poc_worktree, ensure_poc_worktree
from .runtime_capabilities import require_stage56_execution
from .stage_runtime import stage_span
from .stage_state import StageStateStore
from .stages.stage0 import run_setup
from .stages.stage1 import run_stage1
from .stages.stage2 import run_stage2
from .stages.stage3 import run_stage3
from .stages.stage4 import run_stage4
from .stages.stage5 import run_stage5
from .stages.stage6 import run_stage6
from .trajectory import (
    BLOBS_DIRNAME,
    ROOT_FILENAME,
    TrajectoryRecorder,
    atif_totals_from_usage_stats,
    merge_final_metrics,
    relative_trajectory_path,
)

logger = get_logger("orchestrator")

# Backfilling references reads every child document once at the end of a run.
# Bound both the file count and the per-file size so an unrelated/oversized
# JSON file under ``trajectories/`` cannot stall the audit shutdown.
_BACKFILL_MAX_FILES = 2000
_BACKFILL_MAX_FILE_BYTES = 16 * 1024 * 1024


def _run_model(config: AuditConfig) -> str | None:
    """Model id to advertise on the run-level trajectory document."""
    try:
        return resolve_agent_model(config)
    except Exception:  # pragma: no cover - resolution reads local config files
        return None


def _run_extra(
    config: AuditConfig, *, run_kind: str = "audit"
) -> dict[str, object]:
    return {
        "run_kind": run_kind,
        "target": config.target,
        "backend": config.backend,
        "sandbox_enabled": config.sandbox_enabled,
    }


def _start_run_trajectory(
    config: AuditConfig,
    *,
    run_kind: str = "audit",
    system_message: str | None = None,
    user_message: str | None = None,
) -> TrajectoryRecorder | None:
    """Create (or resume) the run-level ATIF document.

    The run-level document records orchestration only: the system/user framing
    and one deterministic delegation step per agent invocation. Token and cost
    totals come from the run's usage accumulator, because those calls belong to
    the child documents.

    On resume the existing document is loaded instead of replaced. Checkpointed
    sub-tasks do not run again, so a fresh document would silently drop the
    references to their child trajectories and start a new session id.
    """
    if not config.trajectory_enabled:
        return None
    root_dir = Path(config.output_dir) / config.trajectory_dirname
    config.trajectory_root_dir = str(root_dir)
    blob_dir = root_dir / BLOBS_DIRNAME
    root_path = root_dir / ROOT_FILENAME

    if config.resume and root_path.is_file():
        try:
            existing = TrajectoryRecorder.load(
                root_path,
                max_inline_bytes=config.trajectory_max_result_bytes,
                max_total_inline_bytes=config.trajectory_max_total_inline_bytes,
                redact=config.trajectory_redact,
                blob_dir=blob_dir,
            )
        except Exception as exc:  # pragma: no cover - defensive
            logger.warning("Could not load the run-level trajectory: %s", exc)
            existing = None
        if existing is not None and existing.steps:
            existing.max_inline_bytes = config.trajectory_max_result_bytes
            existing.max_total_inline_bytes = config.trajectory_max_total_inline_bytes
            existing.redact = config.trajectory_redact
            existing.blob_dir = blob_dir
            existing.model_name = existing.model_name or _run_model(config)
            existing.extend_extra(_run_extra(config, run_kind=run_kind))
            config.trajectory_root = existing
            logger.info(
                "Resuming run-level trajectory %s (%d steps).",
                root_path,
                existing.step_count,
            )
            return existing

    session_id = (
        f"run-{config.sandbox_run_id}"
        if config.sandbox_run_id is not None
        else f"run-{uuid4().hex[:12]}"
    )
    root = TrajectoryRecorder(
        session_id=session_id,
        model_name=_run_model(config),
        max_inline_bytes=config.trajectory_max_result_bytes,
        max_total_inline_bytes=config.trajectory_max_total_inline_bytes,
        redact=config.trajectory_redact,
        blob_dir=blob_dir,
        extra=_run_extra(config, run_kind=run_kind),
    )
    root.system(
        system_message
        or (
            "CodeAuditor multi-stage audit: security-context research, "
            "analysis-unit decomposition, bug discovery, finding evaluation, "
            "PoC reproduction, and disclosure preparation."
        ),
        extra={"run_kind": run_kind},
    )
    root.user(
        user_message
        or f"Audit the repository at {config.target} for security vulnerabilities.",
        extra={
            "scope": config.scope or "",
            "threat_model": config.threat_model,
            "target_au_count": config.target_au_count,
        },
    )
    config.trajectory_root = root
    return root


def start_run_trajectory(
    config: AuditConfig,
    *,
    run_kind: str,
    system_message: str,
    user_message: str,
) -> TrajectoryRecorder | None:
    """Start a run-level trajectory for non-audit maintenance workflows."""
    return _start_run_trajectory(
        config,
        run_kind=run_kind,
        system_message=system_message,
        user_message=user_message,
    )


def finish_run_trajectory(
    config: AuditConfig, root: TrajectoryRecorder | None
) -> None:
    """Publish a previously started run-level trajectory."""
    _finish_run_trajectory(config, root)


def _backfill_subagent_refs(root: TrajectoryRecorder, base: Path) -> int:
    """Reference child documents this process did not register itself.

    Resume and process termination both leave valid child trajectories that the
    just-finished run never saw (a checkpointed task, or a task completed by an
    earlier crashed process). They belong to the same ``session_id``, so they
    can be re-attached without guessing.
    """
    if not root.session_id or not base.is_dir():
        return 0
    added = 0
    for path in sorted(base.rglob("*.json")):
        if added >= _BACKFILL_MAX_FILES:
            logger.warning(
                "Trajectory reference backfill stopped after %d files.", added
            )
            break
        if path == base / ROOT_FILENAME or path.name.endswith(".invalid.json"):
            continue
        if not path.is_file():
            continue
        try:
            if path.stat().st_size > _BACKFILL_MAX_FILE_BYTES:
                continue
        except OSError:
            continue
        try:
            child = TrajectoryRecorder.load(path)
        except Exception as exc:  # pragma: no cover - defensive
            logger.warning("Could not inspect child trajectory %s: %s", path, exc)
            continue
        if child is None or child.step_count == 0:
            continue
        if child.session_id != root.session_id:
            continue
        relative = relative_trajectory_path(path, base)
        if root.has_subagent(relative):
            continue
        parent = path.parent.name if path.parent != base else "agent"
        try:
            root.add_subagent(
                relative,
                label=parent,
                summary=child.summary(),
                trajectory_id=child.trajectory_id,
            )
        except Exception as exc:  # pragma: no cover - defensive
            logger.warning("Could not reference child trajectory %s: %s", path, exc)
            continue
        added += 1
    return added


def _finish_run_trajectory(
    config: AuditConfig, root: TrajectoryRecorder | None
) -> None:
    """Publish the run-level document; never fail the audit over it."""
    if root is None:
        return
    root_dir = config.trajectory_root_dir
    if not root_dir:
        logger.warning("Run-level trajectory has no output directory; skipping write.")
        config.trajectory_root = None
        return
    previous_metrics = dict(root.final_metrics or {})
    try:
        _backfill_subagent_refs(root, Path(root_dir))
        root.finish(usage_totals=atif_totals_from_usage_stats(config.usage_stats))
        if previous_metrics:
            root.final_metrics = merge_final_metrics(
                previous_metrics, root.final_metrics
            )
        root.extend_extra(
            {
                "models_used": list(config.models_used),
                "backends_used": list(config.backends_used),
                "task_errors": len(config.task_errors),
            }
        )
        root.write(Path(root_dir) / ROOT_FILENAME)
    except Exception as exc:
        logger.warning("Could not write the run-level trajectory: %s", exc)
    finally:
        config.trajectory_root = None


class ProgressReporter(Protocol):
    """Receives stage lifecycle updates from the audit pipeline."""

    def begin_stage(self, stage: int, description: str) -> None: ...

    def stage_progress(
        self,
        stage: int,
        items_done: int = 0,
        items_total: int = 0,
        detail: str = "",
    ) -> None: ...

    def end_stage(self, stage: int) -> None: ...


def _select_stage5_vulnerabilities(
    vuln_files: list[str], *, full_analysis: bool = False
) -> list[str]:
    """Select Stage 5 targets, defaulting to Critical/High findings only.

    Full analysis reproduces every evaluated vulnerability. The opt-in
    environment budget can further cap or raise the CVSS threshold.
    """
    try:
        max_items = int(os.environ.get("CODE_AUDITOR_MAX_STAGE5_VULNS", "0"))
    except ValueError:
        max_items = 0
    try:
        min_score = float(os.environ.get("CODE_AUDITOR_MIN_STAGE5_CVSS", "0"))
    except ValueError:
        min_score = 0.0
    env_full = os.environ.get("CODE_AUDITOR_FULL_ANALYSIS", "").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }
    include_all = full_analysis or env_full
    ranked: list[tuple[int, float, str]] = []
    for index, path in enumerate(vuln_files):
        severity = ""
        score = 0.0
        try:
            data = json.loads(Path(path).read_text(encoding="utf-8"))
            if isinstance(data, dict):
                severity = str(data.get("severity") or "").strip().lower()
                score = float(data.get("cvss_score") or 0)
        except (OSError, ValueError, TypeError, json.JSONDecodeError):
            pass
        if not include_all and severity not in {"critical", "high"} and score < 7.0:
            continue
        if score < min_score:
            continue
        ranked.append((index, score, path))
    if max_items > 0:
        ranked.sort(key=lambda item: (-item[1], item[0]))
        ranked = ranked[:max_items]
    selected = [path for _index, _score, path in ranked]
    mode = "full" if include_all else "Critical/High"
    logger.info(
        "Stage 5 selection (%s) selected %d/%d vulnerabilities "
        "(min CVSS %.1f, max items %d).",
        mode,
        len(selected),
        len(vuln_files),
        min_score,
        max_items,
    )
    return selected


async def run_audit(
    config: AuditConfig,
    reporter: ProgressReporter | None = None,
) -> None:
    """Run the audit pipeline, publishing the run-level ATIF trajectory."""
    root = _start_run_trajectory(config)
    try:
        await _run_audit_stages(config, reporter)
    finally:
        _finish_run_trajectory(config, root)


async def _run_audit_stages(
    config: AuditConfig,
    reporter: ProgressReporter | None = None,
) -> None:
    checkpoint = CheckpointManager(config.output_dir, config.resume)
    stage_state = StageStateStore(config.output_dir)
    stage_state.reset(preserve_completed=config.resume)
    if config.resume:
        # Stage 6 is terminal and may be retried after a validation failure.
        # Keep stages 0-5 timings, but never leave Stage 6 marked done while its
        # failed disclosure tasks are running again.
        stage_state.clear(6)
        logger.info("Resume mode enabled. Existing output files and markers will be reused.")

    async with stage_span(
        config, reporter, stage_state, 0, "Setting up output directory"
    ):
        await run_setup(config)

    async with stage_span(
        config, reporter, stage_state, 1, "Researching security context"
    ):
        stage1_out = await run_stage1(config, checkpoint)

    # Resolve directive paths (from stage1 output or default locations)
    stage1 = stage1_paths(config.output_dir)
    auditing_focus_path = (
        stage1_out.auditing_focus_path if stage1_out
        else stage1["focus"]
    )
    vuln_criteria_path = (
        stage1_out.vuln_criteria_path if stage1_out
        else stage1["criteria"]
    )

    async with stage_span(
        config, reporter, stage_state, 2, "Decomposing codebase"
    ) as progress:
        analysis_units = await run_stage2(config, checkpoint, auditing_focus_path)
        if not analysis_units:
            raise RuntimeError("Stage 2 produced no analysis units.")
        progress.update(
            items_done=len(analysis_units),
            items_total=len(analysis_units),
            detail=f"{len(analysis_units)} analysis units found",
        )

    # Stage 3: bug discovery per AU
    total_aus = len(analysis_units)
    async with stage_span(
        config,
        reporter,
        stage_state,
        3,
        f"Discovering bugs across {total_aus} AUs",
    ) as progress:
        bug_files = await run_stage3(
            analysis_units,
            config,
            checkpoint,
            auditing_focus_path,
            vuln_criteria_path,
            progress=progress,
        )
        progress.update(
            items_done=total_aus,
            items_total=total_aus,
            detail=f"{len(bug_files)} findings",
        )

    # Stage 4: evaluate findings
    async with stage_span(
        config,
        reporter,
        stage_state,
        4,
        f"Evaluating {len(bug_files)} findings",
    ) as progress:
        vuln_files = await run_stage4(
            bug_files, config, checkpoint, vuln_criteria_path, progress=progress
        )
        progress.update(
            items_done=len(vuln_files),
            items_total=len(bug_files),
            detail=f"{len(vuln_files)} representative vulnerabilities after semantic dedupe",
        )

    stage5_vuln_files = _select_stage5_vulnerabilities(
        vuln_files, full_analysis=config.full_analysis
    )

    # Stage 5: PoC reproduction per verified vulnerability
    async with stage_span(
        config,
        reporter,
        stage_state,
        5,
        f"Reproducing {len(stage5_vuln_files)} vulnerabilities",
    ) as progress:
        if stage5_vuln_files:
            sandbox_mode = (
                "docker-networked"
                if config.sandbox_enabled and config.sandbox_network_enabled
                else "docker-isolated"
                if config.sandbox_enabled
                else "local-worktree"
            )
            require_stage56_execution(sandbox_mode, config.sandbox_runtime)
        if stage5_vuln_files and not config.sandbox_enabled and config.poc_worktree is None:
            config.poc_worktree = await ensure_poc_worktree(
                config.target, config.output_dir
            )
        stage5_reports = await run_stage5(
            stage5_vuln_files, config, checkpoint, progress=progress
        )
        progress.update(
            items_done=len(stage5_reports),
            items_total=len(stage5_vuln_files),
            detail=f"{len(stage5_reports)} PoCs reproduced",
        )

    # Stage 6: disclosure preparation per reproduced vulnerability
    async with stage_span(
        config,
        reporter,
        stage_state,
        6,
        f"Preparing {len(stage5_reports)} disclosures",
    ) as progress:
        disclosure_reports = await run_stage6(
            stage5_reports, config, checkpoint, progress=progress
        )
        candidate_total = int(
            getattr(config, "stage6_candidate_total", len(stage5_reports))
        )
        progress.update(
            items_done=len(disclosure_reports),
            items_total=candidate_total,
            detail=f"{len(disclosure_reports)} disclosure packages prepared",
        )

    if not config.sandbox_enabled:
        # Retained reports/trajectories are independent of the disposable
        # worktree. Clean it after a terminal Stage 6 result even when some
        # disclosure sub-tasks failed; otherwise a failed run can leave tens of
        # gigabytes of rebuild caches behind indefinitely.
        await cleanup_poc_worktree(
            config.target, config.output_dir, config.poc_worktree
        )

    if config.task_errors:
        logger.error(
            "Audit finished with %d failed agent task(s): %s",
            len(config.task_errors),
            "; ".join(config.task_errors),
        )
    logger.info("Audit complete.")
