"""Multi-job lifecycle manager for the CodeAuditor web UI.

Multiple audits may run concurrently: each job gets its own ``AuditJob``
state holder and ``EventBus``, and the single process-wide ``WebLogHandler``
routes log records to the owning job via the ``CURRENT_JOB_KEY`` context
variable. Concurrency is bounded by ``max_concurrent_jobs`` and jobs that
share a source checkout (the managed repo mirror) are mutually exclusive —
stage 0 ``git pull`` / resume ``git checkout`` mutate the shared mirror and
the commit-stamped output directory would collide.
"""
from __future__ import annotations

import asyncio
import json
import os
import re
import signal
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from uuid import uuid4

from ..checkpoint import CheckpointManager
from ..config import (
    DEFAULT_AGENT_TIMEOUT_SECONDS,
    AgentBackend,
    AuditConfig,
    ProviderMode,
    local_claude_model,
    resolve_wiki_arg,
)
from ..db import RUN_CANCELLED, RUN_DONE, RUN_FAILED, AuditStore, compute_target_key
from ..logger import get_logger
from ..process_tree import (
    CURRENT_AUDIT_PROCESS_MARKER,
    current_audit_subprocess_env,
    snapshot_process_tree,
)
from ..orchestrator import run_audit
from ..repos import (
    DEFAULT_REPOS_DIR,
    DEFAULT_RESULTS_DIR,
    capture_repo_identity,
    create_detached_worktree as repos_create_detached_worktree,
    default_audit_output_dir,
    ensure_repo,
    repo_local_path,
)
from ..stages.stage5 import run_stage5
from ..utils import summarize_task_errors
from ..wikis import DEFAULT_WIKIS_DIR, list_local_wikis
from .progress import CURRENT_JOB_KEY, EventBus, WebProgressReporter

logger = get_logger("web.job")

STATE_IDLE = "idle"
STATE_RESTORING = "restoring"
STATE_RUNNING = "running"
STATE_DONE = "done"
STATE_FAILED = "failed"
STATE_CANCELLED = "cancelled"
BUSY_STATES = {STATE_RESTORING, STATE_RUNNING}
JOB_AUDIT = "audit"
JOB_REPRODUCTION = "reproduction"

DEFAULT_REPRODUCTIONS_DIR = os.path.join("~", ".code_auditor", "reproductions")
DEFAULT_MAX_CONCURRENT_JOBS = 4
FINISHED_JOB_RETENTION_SECONDS = 300.0
RESUME_GIT_TIMEOUT_SECONDS = 60.0
SHUTDOWN_TASK_TIMEOUT_SECONDS = 15.0
INTERRUPTED_AUDIT_ERROR = (
    "Audit interrupted because its Web worker exited before recording a terminal "
    "state. Resume this run from History."
)


class JobConflictError(Exception):
    """Raised when a job cannot start due to a conflicting or too many jobs."""


class JobValidationError(Exception):
    """Raised when job parameters are invalid."""


@dataclass
class AuditStartParams:
    target: str | None = None
    git_url: str | None = None
    output_dir: str | None = None
    wiki: str | None = None
    max_parallel: int = 1
    backend: str = "claude"
    model: str | None = None
    provider_mode: ProviderMode = "local"
    provider_base_url: str | None = None
    provider_api_key: str | None = field(default=None, repr=False)
    target_au_count: int = -1
    log_level: str = "DEBUG"
    repos_dir: str = DEFAULT_REPOS_DIR
    results_dir: str = DEFAULT_RESULTS_DIR


@dataclass
class ReproductionStartParams:
    run_id: int
    vuln_id: str
    backend: str = "claude"
    model: str | None = None
    provider_mode: ProviderMode = "local"
    provider_base_url: str | None = None
    provider_api_key: str | None = field(default=None, repr=False)
    log_level: str = "DEBUG"
    output_dir: str | None = None
    reproductions_dir: str = DEFAULT_REPRODUCTIONS_DIR
    wikis_dir: str = DEFAULT_WIKIS_DIR


def _safe_path_segment(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "-", value).strip("-") or "item"


def _recorded_local_wiki(path: str | None, wikis_dir: str) -> str | None:
    """Reuse a recorded Wiki only while it remains locally managed."""
    if not path:
        return None
    resolved = os.path.realpath(path)
    for candidate in list_local_wikis(wikis_dir):
        if candidate["path"] == resolved:
            return resolved
    return None


def _path_is_within(path: str, root: str) -> bool:
    resolved = os.path.realpath(os.path.expanduser(path))
    managed_root = os.path.realpath(os.path.expanduser(root))
    return resolved == managed_root or resolved.startswith(managed_root + os.sep)


def _local_branch_points_to(target: str, branch: str, commit: str) -> bool:
    """Return whether a safe local branch already names the recorded commit."""
    if (
        not branch
        or branch == "HEAD"
        or branch.startswith("-")
        or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,255}", branch) is None
        or ".." in branch
        or "@{" in branch
        or branch.endswith(("/", ".", ".lock"))
    ):
        return False
    try:
        result = subprocess.run(
            [
                "git",
                "-C",
                target,
                "rev-parse",
                "--verify",
                f"refs/heads/{branch}^{{commit}}",
            ],
            capture_output=True,
            text=True,
            check=False,
            env=current_audit_subprocess_env(),
        )
    except OSError:
        return False
    return result.returncode == 0 and result.stdout.strip() == commit


async def _terminate_resume_git_process(proc: asyncio.subprocess.Process) -> None:
    if proc.returncode is not None:
        return
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    await proc.wait()


async def _run_resume_git_command(
    target: str,
    *args: str,
    timeout_seconds: float = RESUME_GIT_TIMEOUT_SECONDS,
) -> str:
    try:
        proc = await asyncio.create_subprocess_exec(
            "git",
            "-C",
            target,
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            start_new_session=True,
            env=current_audit_subprocess_env(),
        )
    except OSError as exc:
        raise JobValidationError(
            f"Cannot run git while restoring the checkout: {exc}"
        ) from exc
    try:
        output, _ = await asyncio.wait_for(
            proc.communicate(), timeout=timeout_seconds
        )
    except TimeoutError as exc:
        await _terminate_resume_git_process(proc)
        raise JobValidationError(
            "Timed out while restoring the cancelled run checkout with "
            f"`git {' '.join(args)}` after {timeout_seconds:g} seconds."
        ) from exc
    except asyncio.CancelledError:
        await _terminate_resume_git_process(proc)
        raise
    text = (output or b"").decode("utf-8", errors="replace").strip()
    if proc.returncode != 0:
        raise JobValidationError(
            f"Cannot restore the cancelled run checkout with "
            f"`git {' '.join(args)}`: {text[-1000:] or 'git failed'}"
        )
    return text


async def _checkout_recorded_revision(
    target: str,
    commit: str,
    branch: str,
) -> None:
    """Checkout the recorded superproject commit and its exact submodules."""
    if _local_branch_points_to(target, branch, commit):
        checkout_target = branch
        checkout_args = ("checkout", branch)
    else:
        checkout_target = f"detached {commit[:12]}"
        checkout_args = ("checkout", "--detach", commit)
    output = await _run_resume_git_command(target, *checkout_args)
    logger.info(
        "Restored cancelled audit source to %s.%s",
        checkout_target,
        f" git: {output}" if output else "",
    )
    # Update only submodules that were already initialized.  Initializing every
    # QEMU submodule here can download gigabytes, introduces a network
    # dependency, and changes recursive identity output for the same HEAD.
    submodule_output = await _run_resume_git_command(
        target,
        "submodule",
        "update",
        "--checkout",
        "--recursive",
        "--no-fetch",
    )
    logger.info(
        "Restored cancelled audit submodules.%s",
        f" git: {submodule_output}" if submodule_output else "",
    )


async def _create_detached_worktree(repo: str, commit: str, destination: str) -> None:
    """Create an isolated checkout without changing the shared repository."""
    try:
        await repos_create_detached_worktree(repo, commit, destination)
    except RuntimeError as exc:
        raise JobValidationError(str(exc)) from exc


class AuditJob:
    """State and lifecycle for one audit or reproduction job."""

    def __init__(self, manager: "AuditJobManager", kind: str) -> None:
        self.manager = manager
        self.store = manager.store
        self.bus = EventBus()
        self.kind = kind
        self.state: str = STATE_IDLE
        self.error: str = ""
        self.config: AuditConfig | None = None
        self.start_params: AuditStartParams | ReproductionStartParams | None = None
        self.reporter: WebProgressReporter = WebProgressReporter(self.bus)
        self.started_at: float = time.time()
        self.active_started_at: float = self.started_at
        self.duration_seconds: float = 0.0
        self.duration_known: bool = True
        self.ended_at: float = 0.0
        self.task: asyncio.Task | None = None
        self.job_key: str = ""
        self.run_id: int | None = None
        self.process_marker: str = uuid4().hex
        # Realpath of the shared source checkout; used for same-repo mutual
        # exclusion across concurrent jobs.
        self.target_path: str = ""
        self.reproduction_candidate: dict | None = None
        self.reproduction_reports: list[str] = []

    # ── events ────────────────────────────────────────────────────────────

    def publish_job_event(self, **extra: object) -> None:
        """Publish a lifecycle event to the job bus and the global job bus."""
        event = {
            "type": "job",
            "job_key": self.job_key,
            "kind": self.kind,
            "status": self.state,
            "error": self.error,
            "run_id": self.run_id,
            "backend": self.config.backend if self.config else "",
            "model": self.config.model if self.config else None,
            "provider_mode": self.config.provider_mode if self.config else "",
            "backends_used": list(self.config.backends_used) if self.config else [],
            "models_used": list(self.config.models_used) if self.config else [],
            "started_at": self.started_at,
            "duration_seconds": self.duration_seconds,
            "active_started_at": self.active_started_at,
            "duration_known": self.duration_known,
            **extra,
        }
        self.bus.publish(event)
        self.manager.bus.publish(event)

    def _stop_duration_clock(self, ended_at: float) -> None:
        """Fold this active session into the job's accumulated duration once."""
        if not self.active_started_at:
            return
        self.duration_seconds += max(0.0, ended_at - self.active_started_at)
        self.active_started_at = 0.0

    # ── state reconciliation ──────────────────────────────────────────────

    def reconcile(self) -> bool:
        """Release a busy state whose asyncio task has disappeared."""
        if self.state not in BUSY_STATES:
            return False
        if self.task is not None and not self.task.done():
            return False
        self.state = STATE_CANCELLED
        self.error = self.error or INTERRUPTED_AUDIT_ERROR
        self.ended_at = time.time()
        self._stop_duration_clock(self.ended_at)
        if self.store is not None and self.run_id is not None:
            self.store.cancel_running_run(
                self.run_id,
                self.error,
                ended_at=self.ended_at,
            )
        self.publish_job_event()
        logger.warning("Released an interrupted %s scheduler task.", self.kind or "job")
        return True

    async def shutdown(self) -> None:
        """Persist a resumable terminal state before the Web worker exits."""
        self.reconcile()
        if self.state not in BUSY_STATES or self.task is None:
            return
        self.error = INTERRUPTED_AUDIT_ERROR
        task = self.task
        task.cancel()
        done, _ = await asyncio.wait({task}, timeout=SHUTDOWN_TASK_TIMEOUT_SECONDS)
        if not done:
            self.state = STATE_CANCELLED
            self.ended_at = time.time()
            self._stop_duration_clock(self.ended_at)
            if self.store is not None and self.run_id is not None:
                self.store.cancel_running_run(
                    self.run_id,
                    self.error,
                    ended_at=self.ended_at,
                )
            logger.error(
                "Audit task did not stop within %.0f seconds; persisted it as cancelled.",
                SHUTDOWN_TASK_TIMEOUT_SECONDS,
            )
            return
        try:
            task.result()
        except asyncio.CancelledError:
            pass
        except Exception as exc:
            logger.warning("Audit task raised while shutting down: %s", exc)

    def stop(self) -> bool:
        """Cancel the running job. Returns False if it is not running."""
        self.reconcile()
        if self.state not in BUSY_STATES or self.task is None:
            return False
        self.error = ""
        self.task.cancel()
        return True

    def status(self) -> dict:
        self.reconcile()
        return {
            "job_key": self.job_key,
            "kind": self.kind,
            "state": self.state,
            "error": self.error,
            "target": self.config.target if self.config else "",
            "output_dir": self.config.output_dir if self.config else "",
            "started_at": self.started_at,
            "ended_at": self.ended_at,
            "duration_seconds": self.duration_seconds,
            "active_started_at": self.active_started_at,
            "duration_known": self.duration_known,
            "run_id": self.run_id,
            "backend": self.config.backend if self.config else "",
            "model": self.config.model if self.config else None,
            "provider_mode": self.config.provider_mode if self.config else "",
            "backends_used": list(self.config.backends_used) if self.config else [],
            "models_used": list(self.config.models_used) if self.config else [],
            "usage_stats": dict(self.config.usage_stats) if self.config else {},
            "stages": self.reporter.snapshot(),
            "reproduction_candidate": self.reproduction_candidate,
            "reproduction_reports": self.reproduction_reports,
        }

    def process_tree(self) -> dict:
        """Snapshot processes owned by this Audit Run while it is running."""
        self.reconcile()
        if self.kind != JOB_AUDIT or self.state != STATE_RUNNING:
            raise JobConflictError(
                "The process tree is available only while the audit is running."
            )
        return snapshot_process_tree(self.process_marker)

    # ── config / run-row helpers ────────────────────────────────────────────

    def hot_switch_agent_settings(
        self,
        *,
        backend: AgentBackend,
        model: str | None,
        provider_mode: ProviderMode,
        provider_base_url: str | None,
        provider_api_key: str | None,
    ) -> bool:
        """Apply settings to future agent calls without interrupting in-flight calls."""
        self.reconcile()
        if self.state not in BUSY_STATES:
            return False

        effective_model = (
            local_claude_model() or model
            if backend == "claude" and provider_mode == "local"
            else model
        )
        targets = [
            target
            for target in (self.config, self.start_params)
            if target is not None
        ]
        incoming = (
            backend,
            effective_model,
            provider_mode,
            provider_base_url,
            provider_api_key,
        )
        if targets and all(
            (
                target.backend,
                target.model,
                target.provider_mode,
                target.provider_base_url,
                target.provider_api_key,
            )
            == incoming
            for target in targets
        ):
            return False
        previous_backend = (
            self.config.backend
            if self.config is not None
            else self.start_params.backend if self.start_params is not None else ""
        )
        if self.config is not None:
            self.config.backend = backend
            self.config.model = effective_model
            self.config.provider_mode = provider_mode
            self.config.provider_base_url = provider_base_url
            self.config.provider_api_key = provider_api_key
        if self.start_params is not None:
            self.start_params.backend = backend
            self.start_params.model = effective_model
            self.start_params.provider_mode = provider_mode
            self.start_params.provider_base_url = provider_base_url
            self.start_params.provider_api_key = provider_api_key

        if self.store is not None and self.kind == JOB_AUDIT and self.run_id is not None:
            try:
                updated = self.store.update_running_run_agent_settings(
                    self.run_id, backend=backend, model=effective_model
                )
                if self.state == STATE_RUNNING and not updated:
                    logger.warning(
                        "Run #%d switched backend in memory but its active history row "
                        "was not updated.",
                        self.run_id,
                    )
            except Exception as exc:
                logger.warning(
                    "Failed to update Run #%d backend history after hot switch: %s",
                    self.run_id,
                    exc,
                )

        message = (
            f"LLM backend switched from {previous_backend or 'uninitialized'} to {backend}. "
            "In-flight agent calls keep their invocation snapshot; subsequent calls use "
            "the new backend."
        )
        logger.info(message)
        self.bus.publish({"type": "log", "message": message})
        self.publish_job_event(backend_switched=True)
        return True

    def _build_config(
        self, params: AuditStartParams, target: str, wiki_path: str | None
    ) -> AuditConfig:
        if not os.path.isdir(target):
            raise JobValidationError(f"Target directory not found: {target}")
        output_dir = os.path.realpath(
            params.output_dir
            or default_audit_output_dir(target, results_dir=params.results_dir)
        )
        return AuditConfig(
            target=target,
            output_dir=output_dir,
            wiki_path=wiki_path,
            max_parallel=params.max_parallel,
            resume=True,
            log_level=params.log_level,
            backend=params.backend,  # type: ignore[arg-type]
            model=self._resolve_model(params),
            provider_mode=params.provider_mode,
            provider_base_url=params.provider_base_url,
            provider_api_key=params.provider_api_key,
            target_au_count=params.target_au_count,
            agent_timeout_seconds=DEFAULT_AGENT_TIMEOUT_SECONDS,
            known_disclosures=tuple(
                self.store.disclosure_dedupe_index() if self.store else ()
            ),
        )

    def _build_preliminary_config(
        self, params: AuditStartParams, target: str, wiki_path: str | None
    ) -> AuditConfig:
        """Build a config for a repo that has not been cloned yet.

        The output_dir uses a date-based stamp because the commit is unknown
        until the clone completes. ``_run`` updates it afterwards.
        """
        output_dir = os.path.realpath(
            params.output_dir
            or default_audit_output_dir(target, results_dir=params.results_dir)
        )
        return AuditConfig(
            target=target,
            output_dir=output_dir,
            wiki_path=wiki_path,
            max_parallel=params.max_parallel,
            resume=True,
            log_level=params.log_level,
            backend=params.backend,  # type: ignore[arg-type]
            model=self._resolve_model(params),
            provider_mode=params.provider_mode,
            provider_base_url=params.provider_base_url,
            provider_api_key=params.provider_api_key,
            target_au_count=params.target_au_count,
            agent_timeout_seconds=DEFAULT_AGENT_TIMEOUT_SECONDS,
            known_disclosures=tuple(
                self.store.disclosure_dedupe_index() if self.store else ()
            ),
        )

    @staticmethod
    def _resolve_model(params: AuditStartParams) -> str | None:
        """Resolve the effective model for config creation.

        For the claude backend, prefer the model resolved from
        ``~/.claude/settings.json`` so the stored ``run.model`` reflects the
        model agents will actually use, not the web settings fallback.
        """
        if params.backend == "claude" and params.provider_mode == "local":
            return local_claude_model() or params.model
        return params.model

    def _create_run_row(self, config: AuditConfig) -> None:
        if self.store is None:
            return
        try:
            self.run_id = self.store.create_run(config, started_at=self.started_at)
        except Exception as e:
            logger.warning("Failed to create history database run row: %s", e)

    def _seed_analysis_units(self, config: AuditConfig) -> None:
        """Reuse analysis units from a previous audit of the same repo+commit."""
        if self.store is None:
            return
        try:
            target_key = compute_target_key(capture_repo_identity(config.target))
            seeded = self.store.seed_analysis_units(target_key, config.output_dir)
            if seeded:
                logger.info(
                    "Reused %d analysis units from a previous audit of this commit.",
                    seeded,
                )
        except Exception as e:
            logger.warning("Failed to seed analysis units: %s", e)

    # ── audit pipeline ──────────────────────────────────────────────────────

    async def _run(
        self,
        config: AuditConfig | None,
        params: AuditStartParams,
        wiki_path: str | None,
    ) -> None:
        try:
            if params.git_url:
                target = await ensure_repo(params.git_url, params.repos_dir)
                prev_output_dir = config.output_dir if config else None
                config = self._build_config(params, target, wiki_path)
                self.config = config
                if (
                    self.store is not None
                    and self.run_id is not None
                    and prev_output_dir
                    and config.output_dir != prev_output_dir
                ):
                    self.store.update_run_output_dir(
                        self.run_id, config.output_dir
                    )
            assert config is not None
            # Repository identity collection invokes several synchronous Git
            # commands.  This task is scheduled before the start endpoint has
            # necessarily flushed its 202 response, so never run that work on
            # the event loop.
            await asyncio.to_thread(self._seed_analysis_units, config)
            logger.info("Starting audit of %s (web UI)", config.target)
            await run_audit(config, tui=self.reporter)
            self.error = summarize_task_errors(config.task_errors)
            self.state = STATE_FAILED if self.error else STATE_DONE
        except asyncio.CancelledError:
            self.state = STATE_CANCELLED
            logger.info("Audit cancelled.")
        except Exception as e:
            self.state = STATE_FAILED
            self.error = str(e)
            logger.exception("Audit failed: %s", e)
        finally:
            if self.state in BUSY_STATES:
                self.state = STATE_CANCELLED
                self.error = self.error or INTERRUPTED_AUDIT_ERROR
            self.ended_at = time.time()
            self._stop_duration_clock(self.ended_at)
            if self.store is not None and self.run_id is not None:
                try:
                    self.store.finish_run(
                        self.run_id,
                        self.state,
                        self.error,
                        self.ended_at,
                        backends_used=list(config.backends_used) if config else None,
                        models_used=list(config.models_used) if config else None,
                        usage_stats=dict(config.usage_stats) if config else None,
                    )
                except Exception as e:
                    logger.warning("Failed to update history database run row: %s", e)
            self.publish_job_event()

    async def _restore_and_run_cancelled(
        self,
        *,
        run_id: int,
        target: str,
        recorded_commit: str,
        recorded_target_key: str,
        branch: str,
        config: AuditConfig,
        params: AuditStartParams,
        wiki_path: str | None,
    ) -> None:
        """Restore a pinned checkout, then continue the existing audit."""
        assert self.store is not None
        try:
            logger.info(
                "Restoring Run #%d to commit %s.",
                run_id,
                recorded_commit,
            )
            identity = capture_repo_identity(target)
            if identity.get("dirty"):
                # Older runs let PoC agents work inside the shared mirror,
                # which could leave it dirty. Stash the leftovers instead of
                # refusing.
                await _stash_resume_leftovers(target, run_id)
                identity = capture_repo_identity(target)
                if identity.get("dirty"):
                    raise JobValidationError(
                        "The source checkout still has uncommitted or untracked "
                        "changes after an automatic `git stash`; clean it before "
                        "continuing."
                    )
            await _checkout_recorded_revision(target, recorded_commit, branch)
            identity = capture_repo_identity(target)
            if identity.get("dirty"):
                raise JobValidationError(
                    "The restored source checkout is dirty after checkout/submodule update."
                )
            if identity.get("commit") != recorded_commit:
                raise JobValidationError(
                    "The restored source checkout does not match the cancelled run commit "
                    f"({recorded_commit[:12]})."
                )
            if compute_target_key(identity) != recorded_target_key:
                raise JobValidationError(
                    "The source or submodule identity no longer matches the cancelled run."
                )
            if not self.store.resume_cancelled_run(
                run_id,
                resumed_at=self.active_started_at,
                backend=config.backend,
                model=config.model,
            ):
                raise JobConflictError(
                    "The run is no longer resumable; refresh History and try again."
                )
        except asyncio.CancelledError:
            self.state = STATE_CANCELLED
            logger.info("Cancelled audit restoration stopped.")
            self._finish_restore_attempt()
            return
        except Exception as exc:
            self.state = STATE_FAILED
            self.error = str(exc)
            logger.exception("Cancelled audit restoration failed: %s", exc)
            self._finish_restore_attempt()
            return

        self.state = STATE_RUNNING
        self.publish_job_event(target=target, resumed=True)
        await self._run(config, params, wiki_path)

    def _finish_restore_attempt(self) -> None:
        self.ended_at = time.time()
        self._stop_duration_clock(self.ended_at)
        self.publish_job_event()

    # ── reproduction pipeline ───────────────────────────────────────────────

    async def _run_reproduction(
        self,
        params: ReproductionStartParams,
        candidate: dict,
        reproduction_root: str,
    ) -> None:
        worktree = os.path.join(reproduction_root, "source")
        output_dir = os.path.join(reproduction_root, "output")
        try:
            logger.info(
                "Preparing isolated reproduction of Run #%s %s at %s.",
                candidate["run_id"],
                candidate["vuln_id"],
                candidate["commit"],
            )
            await _create_detached_worktree(
                candidate["target"], candidate["commit"], worktree
            )
            vuln_dir = Path(output_dir) / "stage4-vulnerabilities"
            vuln_dir.mkdir(parents=True, exist_ok=True)
            vuln_path = vuln_dir / f"{_safe_path_segment(candidate['vuln_id'])}.json"
            raw = json.loads(candidate["raw_json"])
            vuln_path.write_text(
                json.dumps(raw, indent=2, ensure_ascii=False) + "\n",
                encoding="utf-8",
            )
            self.config = AuditConfig(
                target=worktree,
                output_dir=output_dir,
                wiki_path=_recorded_local_wiki(
                    candidate.get("wiki_path"), params.wikis_dir
                ),
                max_parallel=1,
                resume=False,
                log_level=params.log_level,
                backend=params.backend,  # type: ignore[arg-type]
                model=params.model,
                provider_mode=params.provider_mode,
                provider_base_url=params.provider_base_url,
                provider_api_key=params.provider_api_key,
                agent_timeout_seconds=DEFAULT_AGENT_TIMEOUT_SECONDS,
            )
            self.reporter.begin_stage(
                5, f"Retesting Run #{candidate['run_id']} {candidate['vuln_id']}"
            )
            checkpoint = CheckpointManager(output_dir, resume=False)
            self.reproduction_reports = await run_stage5(
                [str(vuln_path)], self.config, checkpoint
            )
            self.reporter.stage_progress(
                5,
                items_done=len(self.reproduction_reports),
                items_total=1,
                detail=(
                    "Reproduced"
                    if self.reproduction_reports
                    else "Not reproduced"
                ),
            )
            self.reporter.end_stage(5)
            self.state = STATE_DONE
        except asyncio.CancelledError:
            self.state = STATE_CANCELLED
            logger.info("Reproduction cancelled.")
        except Exception as e:
            self.state = STATE_FAILED
            self.error = str(e)
            logger.exception("Reproduction failed: %s", e)
        finally:
            if self.state in BUSY_STATES:
                self.state = STATE_CANCELLED
                self.error = self.error or INTERRUPTED_AUDIT_ERROR
            self.ended_at = time.time()
            self._stop_duration_clock(self.ended_at)
            self.publish_job_event()


async def _stash_resume_leftovers(target: str, run_id: int) -> None:
    """Stash tracked leftover changes (e.g. from older PoC agents) before resume."""
    output = await _run_resume_git_command(
        target,
        "stash",
        "push",
        "-m",
        f"code-auditor auto-stash before resuming run #{run_id}",
    )
    logger.warning(
        "Auto-stashed leftover changes in %s before resuming run #%d.%s",
        target,
        run_id,
        f" git: {output}" if output else "",
    )


class AuditJobManager:
    """Registry of concurrently running web jobs.

    Jobs are keyed by ``job_key`` (the run id for audits, a generated id for
    reproductions). Starting a job is atomic with respect to other starts:
    validation and registration happen synchronously before the job's
    asyncio task is created, so the conflict checks below cannot interleave
    on the single event loop.
    """

    def __init__(
        self,
        store: AuditStore | None = None,
        *,
        max_concurrent_jobs: int = DEFAULT_MAX_CONCURRENT_JOBS,
    ) -> None:
        self.store = store
        self.max_concurrent_jobs = max(1, max_concurrent_jobs)
        # Global lifecycle bus: every job's "job" events, run-tagged, for the
        # sidebar / History live badges.
        self.bus = EventBus()
        self._jobs: dict[str, AuditJob] = {}

    # ── registry ────────────────────────────────────────────────────────────

    def get_job(self, job_key: str) -> AuditJob | None:
        job = self._jobs.get(job_key)
        if job is not None:
            job.reconcile()
        return job

    def bus_for_job(self, job_key: str) -> EventBus | None:
        """EventBus lookup used by the process-wide web log handler."""
        job = self._jobs.get(job_key)
        return job.bus if job is not None else None

    def list_jobs(self) -> list[dict]:
        self._prune_finished_jobs()
        return [job.status() for job in self._jobs.values()]

    def _active_jobs(self) -> list[AuditJob]:
        active = []
        for job in self._jobs.values():
            job.reconcile()
            if job.state in BUSY_STATES:
                active.append(job)
        return active

    def _prune_finished_jobs(self) -> None:
        now = time.time()
        for key, job in list(self._jobs.items()):
            job.reconcile()
            if (
                job.state not in BUSY_STATES
                and job.ended_at
                and now - job.ended_at > FINISHED_JOB_RETENTION_SECONDS
            ):
                del self._jobs[key]

    def _check_start_allowed(
        self, target_path: str | None, run_id: int | None = None
    ) -> None:
        active = self._active_jobs()
        if len(active) >= self.max_concurrent_jobs:
            raise JobConflictError(
                f"Concurrent job limit reached ({self.max_concurrent_jobs}); "
                "wait for a running job to finish or stop one."
            )
        for job in active:
            if run_id is not None and job.run_id == run_id:
                raise JobConflictError(f"Run #{run_id} already has a running job.")
            if target_path and job.target_path == target_path:
                raise JobConflictError(
                    "A job is already running for this repository; concurrent "
                    "jobs must target different repositories."
                )

    def _register(self, job: AuditJob) -> AuditJob:
        self._jobs[job.job_key] = job
        return job

    @staticmethod
    def _launch(job: AuditJob, coroutine) -> None:
        """Start the job task with the log-routing context variable set."""
        job_token = CURRENT_JOB_KEY.set(job.job_key)
        process_token = CURRENT_AUDIT_PROCESS_MARKER.set(job.process_marker)
        try:
            job.task = asyncio.create_task(coroutine)
        finally:
            CURRENT_AUDIT_PROCESS_MARKER.reset(process_token)
            CURRENT_JOB_KEY.reset(job_token)

    # ── lifecycle ───────────────────────────────────────────────────────────

    def recover_interrupted_runs(self) -> list[int]:
        """Recover database rows that no task in this Web worker can own."""
        if self.store is None:
            return []
        if self._active_jobs():
            return []
        run_ids = self.store.cancel_running_runs(INTERRUPTED_AUDIT_ERROR)
        if run_ids:
            logger.warning(
                "Recovered interrupted audit run(s) as cancelled: %s.",
                ", ".join(f"#{run_id}" for run_id in run_ids),
            )
        return run_ids

    async def shutdown(self) -> None:
        """Persist resumable terminal states before the Web worker exits."""
        await asyncio.gather(
            *(job.shutdown() for job in list(self._jobs.values())),
            return_exceptions=True,
        )

    def stop(self, job_key: str) -> AuditJob | None:
        """Cancel one job. Returns the job, or None if it was not running."""
        job = self.get_job(job_key)
        if job is None or not job.stop():
            return None
        return job

    async def start(self, params: AuditStartParams) -> AuditJob:
        self._prune_finished_jobs()
        if bool(params.git_url) == bool(params.target):
            raise JobValidationError(
                "Select exactly one existing repository or Git repository URL."
            )
        try:
            wiki_path = resolve_wiki_arg(params.wiki)
        except ValueError as e:
            raise JobValidationError(str(e)) from e

        config: AuditConfig | None = None
        if params.git_url:
            # Pre-compute the target path so the run appears in History
            # immediately, before the clone finishes inside _run().
            target = repo_local_path(params.git_url, params.repos_dir)
            target_path = os.path.realpath(target)
            job = AuditJob(self, JOB_AUDIT)
            if os.path.isdir(target):
                config = job._build_config(params, target_path, wiki_path)
            else:
                config = job._build_preliminary_config(params, target_path, wiki_path)
        else:
            target_path = os.path.realpath(params.target or "")
            job = AuditJob(self, JOB_AUDIT)
            config = job._build_config(params, target_path, wiki_path)

        self._check_start_allowed(target_path)
        job.target_path = target_path
        job.config = config
        job.start_params = params
        job.state = STATE_RUNNING
        job._create_run_row(config)
        job.job_key = (
            str(job.run_id)
            if job.run_id is not None
            else f"audit-{uuid4().hex[:12]}"
        )
        self._register(job)
        job.publish_job_event(target=params.target or params.git_url)
        self._launch(job, job._run(config, params, wiki_path))
        return job

    async def resume_cancelled(
        self,
        run_id: int,
        *,
        repos_dir: str = DEFAULT_REPOS_DIR,
        results_dir: str = DEFAULT_RESULTS_DIR,
        wikis_dir: str = DEFAULT_WIKIS_DIR,
        backend: AgentBackend | None = None,
        provider_mode: ProviderMode = "local",
        provider_base_url: str | None = None,
        provider_api_key: str | None = None,
        model: str | None = None,
    ) -> AuditJob:
        """Start restoring a cancelled audit in its original output directory."""
        self._prune_finished_jobs()
        if self.store is None:
            raise JobValidationError("The history database is unavailable.")

        run = self.store.get_run(run_id)
        if run is None:
            raise JobValidationError(f"Run not found: {run_id}")
        run_status = str(run.get("status") or "")
        if run_status not in (RUN_CANCELLED, RUN_FAILED) and not (
            run_status == RUN_DONE and run.get("error")
        ):
            raise JobValidationError(
                "Only cancelled, failed, or partially failed (done with errors) "
                "audit runs can be continued."
            )
        if run.get("dirty"):
            raise JobValidationError(
                "This run was recorded from a dirty checkout and cannot be safely continued."
            )

        recorded_backend = str(run.get("backend") or "")
        selected_backend = backend or recorded_backend
        if selected_backend not in {"claude", "codex"}:
            raise JobValidationError(
                f"Unsupported selected backend: {selected_backend or 'empty'}"
            )
        selected_model = (
            local_claude_model() or model
            if selected_backend == "claude" and provider_mode == "local"
            else model
        )

        target = os.path.realpath(run.get("target") or "")
        output_dir = os.path.realpath(run.get("output_dir") or "")
        if not _path_is_within(target, repos_dir):
            raise JobValidationError(
                "The recorded source is outside the managed repository directory."
            )
        if not _path_is_within(output_dir, results_dir):
            raise JobValidationError(
                "The recorded output is outside the managed results directory."
            )
        # Clone never completed: target dir absent and no identity was ever recorded.
        # Re-dispatch as a fresh clone reusing the existing run row.
        if not os.path.isdir(target) and not run.get("commit") and not run.get("target_key"):
            repos_root = os.path.realpath(os.path.expanduser(repos_dir))
            rel = os.path.relpath(target, repos_root)
            git_url = "https://" + rel.replace(os.sep, "/")
            max_parallel = run.get("max_parallel")
            target_au_count = run.get("target_au_count")
            if not isinstance(max_parallel, int) or not 1 <= max_parallel <= 16:
                raise JobValidationError("The recorded max_parallel value is invalid.")
            if not isinstance(target_au_count, int) or (
                target_au_count != -1 and target_au_count < 1
            ):
                raise JobValidationError("The recorded target analysis-unit count is invalid.")
            wiki_path = _recorded_local_wiki(run.get("wiki_path"), wikis_dir)
            clone_params = AuditStartParams(
                git_url=git_url,
                repos_dir=repos_dir,
                results_dir=results_dir,
                max_parallel=max_parallel,
                backend=selected_backend,
                model=selected_model,
                provider_mode=provider_mode,
                provider_base_url=provider_base_url,
                provider_api_key=provider_api_key,
                target_au_count=target_au_count,
                log_level=str(run.get("log_level") or "INFO"),
                wiki=wiki_path,
            )
            self._check_start_allowed(target, run_id=run_id)
            job = AuditJob(self, JOB_AUDIT)
            config = job._build_preliminary_config(clone_params, target, wiki_path)
            job.duration_seconds = max(float(run.get("duration_seconds") or 0), 0.0)
            job.duration_known = bool(run.get("duration_known", True))
            if not self.store.resume_cancelled_run(
                run_id,
                resumed_at=job.active_started_at,
                backend=config.backend,
                model=config.model,
            ):
                raise JobConflictError(
                    "The run is no longer resumable; refresh History and try again."
                )
            job.target_path = target
            job.config = config
            job.start_params = clone_params
            job.state = STATE_RUNNING
            job.run_id = run_id
            job.job_key = str(run_id)
            self._register(job)
            job.publish_job_event(target=git_url, resumed=True)
            self._launch(job, job._run(config, clone_params, wiki_path))
            return job

        if not os.path.isdir(target):
            raise JobValidationError(f"Source repository not found: {target}")
        if not os.path.isdir(output_dir):
            raise JobValidationError(f"Audit output directory not found: {output_dir}")

        recorded_commit = str(run.get("commit") or "")
        recorded_target_key = str(run.get("target_key") or "")
        if (
            re.fullmatch(r"[0-9a-fA-F]{40}|[0-9a-fA-F]{64}", recorded_commit)
            is None
            or not recorded_target_key
        ):
            raise JobValidationError(
                "The cancelled run has no pinned source identity and cannot be safely continued."
            )

        max_parallel = run.get("max_parallel")
        target_au_count = run.get("target_au_count")
        if not isinstance(max_parallel, int) or not 1 <= max_parallel <= 16:
            raise JobValidationError("The recorded max_parallel value is invalid.")
        if not isinstance(target_au_count, int) or (
            target_au_count != -1 and target_au_count < 1
        ):
            raise JobValidationError("The recorded target analysis-unit count is invalid.")

        wiki_path = _recorded_local_wiki(run.get("wiki_path"), wikis_dir)
        if run.get("wiki_path") and wiki_path is None:
            raise JobValidationError(
                "The recorded Wiki is no longer available under the managed Wiki directory."
            )
        config = AuditConfig(
            target=target,
            output_dir=output_dir,
            wiki_path=wiki_path,
            max_parallel=max_parallel,
            resume=True,
            update_repo=False,
            log_level=str(run.get("log_level") or "INFO"),
            backend=selected_backend,  # type: ignore[arg-type]
            # Do not pin the recorded model id: providers rename models, so
            # resolve it fresh from the local Claude config at agent time.
            model=selected_model,
            provider_mode=provider_mode,
            provider_base_url=provider_base_url,
            provider_api_key=provider_api_key,
            target_au_count=target_au_count,
            agent_timeout_seconds=DEFAULT_AGENT_TIMEOUT_SECONDS,
            known_disclosures=tuple(self.store.disclosure_dedupe_index()),
        )
        # Carry forward the original session's accounting: finish_run writes
        # these collectors wholesale, so seed them from the run row or the
        # earlier session's backend/model/cost history would be lost.
        try:
            prior_backends = json.loads(str(run.get("backends_used") or "[]"))
        except ValueError:
            prior_backends = []
        if not isinstance(prior_backends, list) or not prior_backends:
            prior_backends = [recorded_backend] if recorded_backend else []
        for prior_backend in prior_backends:
            backend_name = str(prior_backend)
            if (
                backend_name in {"claude", "codex"}
                and backend_name not in config.backends_used
            ):
                config.backends_used.append(backend_name)
        try:
            prior_models = json.loads(str(run.get("models_used") or "[]"))
        except ValueError:
            prior_models = []
        if isinstance(prior_models, list):
            config.models_used.extend(str(m) for m in prior_models)
        try:
            prior_usage = json.loads(str(run.get("usage_stats") or "{}"))
        except ValueError:
            prior_usage = {}
        if isinstance(prior_usage, dict):
            for key, value in prior_usage.items():
                try:
                    config.usage_stats[str(key)] = float(value)
                except (TypeError, ValueError):
                    continue
        params = AuditStartParams(
            target=target,
            output_dir=output_dir,
            wiki=wiki_path,
            max_parallel=max_parallel,
            backend=selected_backend,
            model=config.model,
            provider_mode=provider_mode,
            provider_base_url=provider_base_url,
            provider_api_key=provider_api_key,
            target_au_count=target_au_count,
            log_level=config.log_level,
            repos_dir=repos_dir,
            results_dir=results_dir,
        )
        self._check_start_allowed(target, run_id=run_id)
        job = AuditJob(self, JOB_AUDIT)
        job.duration_seconds = max(float(run.get("duration_seconds") or 0), 0.0)
        job.duration_known = bool(run.get("duration_known", True))
        job.target_path = target
        job.config = config
        job.start_params = params
        job.state = STATE_RESTORING
        job.run_id = run_id
        job.job_key = str(run_id)
        self._register(job)
        job.publish_job_event(target=target, resumed=True)
        self._launch(
            job,
            job._restore_and_run_cancelled(
                run_id=run_id,
                target=target,
                recorded_commit=recorded_commit,
                recorded_target_key=recorded_target_key,
                branch=str(run.get("branch") or ""),
                config=config,
                params=params,
                wiki_path=wiki_path,
            ),
        )
        return job

    async def start_reproduction(self, params: ReproductionStartParams) -> AuditJob:
        """Retest one exactly reproduced History vulnerability in isolation."""
        self._prune_finished_jobs()
        if self.store is None:
            raise JobValidationError("The history database is unavailable.")
        candidate = self.store.get_reproduction_candidate(
            params.run_id, params.vuln_id
        )
        if candidate is None:
            raise JobValidationError(
                "The selected vulnerability is missing or is not exactly reproduced."
            )
        if not candidate.get("commit"):
            raise JobValidationError("The selected History run has no source commit.")
        if not os.path.isdir(candidate["target"]):
            raise JobValidationError(
                f"Source repository not found: {candidate['target']}"
            )

        repo_name = _safe_path_segment(candidate.get("repo_name") or "repo")
        vuln_segment = _safe_path_segment(candidate["vuln_id"])
        stamp = time.strftime("%Y%m%d-%H%M%S")
        unique_suffix = str(time.time_ns())[-6:]
        reproduction_root = os.path.realpath(
            os.path.expanduser(
                params.output_dir
                or os.path.join(
                    params.reproductions_dir,
                    repo_name,
                    candidate["commit"][:12],
                    vuln_segment,
                    f"{stamp}-{unique_suffix}",
                )
            )
        )
        if os.path.exists(reproduction_root):
            raise JobValidationError(
                f"Reproduction output already exists: {reproduction_root}"
            )

        self._check_start_allowed(os.path.realpath(candidate["target"]))
        job = AuditJob(self, JOB_REPRODUCTION)
        job.start_params = params
        job.target_path = os.path.realpath(candidate["target"])
        job.state = STATE_RUNNING
        job.run_id = None
        job.job_key = f"repro-{uuid4().hex[:12]}"
        job.reproduction_candidate = {
            key: candidate.get(key)
            for key in (
                "run_id",
                "vuln_id",
                "title",
                "repo_name",
                "commit",
                "severity",
                "cvss_score",
            )
        }
        self._register(job)
        job.publish_job_event(
            target=candidate["target"],
            source_run_id=candidate["run_id"],
            vuln_id=candidate["vuln_id"],
        )
        self._launch(job, job._run_reproduction(params, candidate, reproduction_root))
        return job

    def hot_switch_agent_settings(
        self,
        *,
        backend: AgentBackend,
        model: str | None,
        provider_mode: ProviderMode,
        provider_base_url: str | None,
        provider_api_key: str | None,
    ) -> list[str]:
        """Apply one provider selection to every active audit/reproduction job."""
        switched: list[str] = []
        for job in self._active_jobs():
            if job.hot_switch_agent_settings(
                backend=backend,
                model=model,
                provider_mode=provider_mode,
                provider_base_url=provider_base_url,
                provider_api_key=provider_api_key,
            ):
                switched.append(job.job_key)
        return switched
