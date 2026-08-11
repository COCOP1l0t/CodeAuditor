"""Single-job lifecycle manager for the CodeAuditor web UI.

Only one audit may run at a time: logging is configured globally, the agent
backends are monkey-patched at import time, and checkpoints are per output
directory. ``AuditJobManager`` therefore models a single current/last job.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import signal
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

from ..checkpoint import CheckpointManager
from ..config import (
    DEFAULT_AGENT_TIMEOUT_SECONDS,
    AuditConfig,
    local_claude_model,
    resolve_wiki_arg,
)
from ..db import RUN_CANCELLED, RUN_DONE, RUN_FAILED, AuditStore, compute_target_key
from ..logger import get_logger
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
from .progress import EventBus, WebLogHandler, WebProgressReporter

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
RESUME_GIT_TIMEOUT_SECONDS = 60.0
SHUTDOWN_TASK_TIMEOUT_SECONDS = 15.0
INTERRUPTED_AUDIT_ERROR = (
    "Audit interrupted because its Web worker exited before recording a terminal "
    "state. Resume this run from History."
)


class JobConflictError(Exception):
    """Raised when starting a job while another one is running."""


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
    def __init__(self, store: AuditStore | None = None) -> None:
        self.bus = EventBus()
        self.store = store
        self.state: str = STATE_IDLE
        self.kind: str = ""
        self.error: str = ""
        self.config: AuditConfig | None = None
        self.reporter: WebProgressReporter | None = None
        self.started_at: float = 0.0
        self.ended_at: float = 0.0
        self._task: asyncio.Task | None = None
        self._log_handler: WebLogHandler | None = None
        self._run_id: int | None = None
        self.reproduction_candidate: dict | None = None
        self.reproduction_reports: list[str] = []

    def recover_interrupted_runs(self) -> list[int]:
        """Recover database rows that no task in this Web worker can own."""
        if self.store is None:
            return []
        if (
            self.state in BUSY_STATES
            and self._task is not None
            and not self._task.done()
        ):
            return []
        run_ids = self.store.cancel_running_runs(INTERRUPTED_AUDIT_ERROR)
        if run_ids:
            logger.warning(
                "Recovered interrupted audit run(s) as cancelled: %s.",
                ", ".join(f"#{run_id}" for run_id in run_ids),
            )
        return run_ids

    def _reconcile_task_state(self) -> bool:
        """Release a busy scheduler state whose asyncio task has disappeared."""
        if self.state not in BUSY_STATES:
            return False
        if self._task is not None and not self._task.done():
            return False
        self.state = STATE_CANCELLED
        self.error = self.error or INTERRUPTED_AUDIT_ERROR
        self.ended_at = time.time()
        self._remove_log_handler()
        if self.store is not None and self._run_id is not None:
            self.store.cancel_running_run(
                self._run_id,
                self.error,
                ended_at=self.ended_at,
            )
        self.bus.publish(
            {
                "type": "job",
                "kind": self.kind,
                "status": self.state,
                "error": self.error,
            }
        )
        logger.warning("Released an interrupted %s scheduler task.", self.kind or "job")
        return True

    async def shutdown(self) -> None:
        """Persist a resumable terminal state before the Web worker exits."""
        self._reconcile_task_state()
        if self.state not in BUSY_STATES or self._task is None:
            return
        self.error = INTERRUPTED_AUDIT_ERROR
        task = self._task
        task.cancel()
        done, _ = await asyncio.wait(
            {task}, timeout=SHUTDOWN_TASK_TIMEOUT_SECONDS
        )
        if not done:
            self.state = STATE_CANCELLED
            self.ended_at = time.time()
            self._remove_log_handler()
            if self.store is not None and self._run_id is not None:
                self.store.cancel_running_run(
                    self._run_id,
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

    async def start(self, params: AuditStartParams) -> None:
        self._reconcile_task_state()
        if self.state in BUSY_STATES:
            raise JobConflictError("An audit is already running.")
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
            if os.path.isdir(target):
                config = self._build_config(params, target, wiki_path)
            else:
                config = self._build_preliminary_config(
                    params, target, wiki_path
                )
        else:
            config = self._build_config(
                params, os.path.realpath(params.target or ""), wiki_path
            )

        self.bus.clear()
        self.reporter = WebProgressReporter(self.bus)
        self._install_log_handler()

        self.config = config
        self.kind = JOB_AUDIT
        self.state = STATE_RUNNING
        self.error = ""
        self.started_at = time.time()
        self.ended_at = 0.0
        self._run_id = None
        self.reproduction_candidate = None
        self.reproduction_reports = []
        self._create_run_row(config)
        self.bus.publish(
            {
                "type": "job",
                "kind": self.kind,
                "status": STATE_RUNNING,
                "target": params.target or params.git_url,
            }
        )

        self._task = asyncio.create_task(self._run(config, params, wiki_path))

    async def resume_cancelled(
        self,
        run_id: int,
        *,
        repos_dir: str = DEFAULT_REPOS_DIR,
        results_dir: str = DEFAULT_RESULTS_DIR,
        wikis_dir: str = DEFAULT_WIKIS_DIR,
    ) -> None:
        """Start restoring a cancelled audit in its original output directory."""
        self._reconcile_task_state()
        if self.state in BUSY_STATES:
            raise JobConflictError("An audit or reproduction is already running.")
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
        current_identity = capture_repo_identity(target)
        if current_identity.get("dirty"):
            # Older runs let PoC agents work inside the shared mirror, which
            # could leave it dirty. Stash the leftovers instead of refusing.
            await _stash_resume_leftovers(target, run_id)
            current_identity = capture_repo_identity(target)
            if current_identity.get("dirty"):
                raise JobValidationError(
                    "The source checkout still has uncommitted or untracked changes "
                    "after an automatic `git stash`; clean it before continuing."
                )

        backend = str(run.get("backend") or "")
        if backend not in {"claude", "codex"}:
            raise JobValidationError(f"Unsupported recorded backend: {backend or 'empty'}")
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
            backend=backend,  # type: ignore[arg-type]
            # Do not pin the recorded model id: providers rename models, so
            # resolve it fresh from the local Claude config at agent time.
            model=None,
            target_au_count=target_au_count,
            agent_timeout_seconds=DEFAULT_AGENT_TIMEOUT_SECONDS,
            known_disclosures=tuple(self.store.disclosure_dedupe_index()),
        )
        # Carry forward the original session's accounting: finish_run writes
        # config.models_used / config.usage_stats wholesale, so seed them from
        # the run row or the earlier session's models/costs would be lost.
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
            backend=backend,
            model=config.model,
            target_au_count=target_au_count,
            log_level=config.log_level,
            repos_dir=repos_dir,
            results_dir=results_dir,
        )
        self.bus.clear()
        self.reporter = WebProgressReporter(self.bus)
        self._install_log_handler()
        self.config = config
        self.kind = JOB_AUDIT
        self.state = STATE_RESTORING
        self.error = ""
        self.started_at = time.time()
        self.ended_at = 0.0
        self._run_id = run_id
        self.reproduction_candidate = None
        self.reproduction_reports = []
        self.bus.publish(
            {
                "type": "job",
                "kind": self.kind,
                "status": STATE_RESTORING,
                "target": target,
                "run_id": run_id,
                "resumed": True,
            }
        )
        self._task = asyncio.create_task(
            self._restore_and_run_cancelled(
                run_id=run_id,
                target=target,
                recorded_commit=recorded_commit,
                recorded_target_key=recorded_target_key,
                branch=str(run.get("branch") or ""),
                config=config,
                params=params,
                wiki_path=wiki_path,
            )
        )

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
                raise JobValidationError(
                    "The source checkout changed and is now dirty; clean it before continuing."
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
            if not self.store.resume_cancelled_run(run_id):
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
        self.bus.publish(
            {
                "type": "job",
                "kind": self.kind,
                "status": STATE_RUNNING,
                "target": target,
                "run_id": run_id,
                "resumed": True,
            }
        )
        await self._run(config, params, wiki_path)

    def _finish_restore_attempt(self) -> None:
        self.ended_at = time.time()
        self._remove_log_handler()
        self.bus.publish(
            {
                "type": "job",
                "kind": self.kind,
                "status": self.state,
                "error": self.error,
            }
        )

    async def start_reproduction(self, params: ReproductionStartParams) -> None:
        """Retest one exactly reproduced History vulnerability in isolation."""
        self._reconcile_task_state()
        if self.state in BUSY_STATES:
            raise JobConflictError("An audit or reproduction is already running.")
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

        self.bus.clear()
        self.reporter = WebProgressReporter(self.bus)
        self._install_log_handler()
        self.kind = JOB_REPRODUCTION
        self.config = None
        self.state = STATE_RUNNING
        self.error = ""
        self.started_at = time.time()
        self.ended_at = 0.0
        self._run_id = None
        self.reproduction_candidate = {
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
        self.reproduction_reports = []
        self.bus.publish(
            {
                "type": "job",
                "kind": self.kind,
                "status": STATE_RUNNING,
                "target": candidate["target"],
                "run_id": candidate["run_id"],
                "vuln_id": candidate["vuln_id"],
            }
        )
        self._task = asyncio.create_task(
            self._run_reproduction(params, candidate, reproduction_root)
        )

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
        if params.backend == "claude":
            return local_claude_model() or params.model
        return params.model

    def _create_run_row(self, config: AuditConfig) -> None:
        if self.store is None:
            return
        try:
            self._run_id = self.store.create_run(config, started_at=self.started_at)
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
                    and self._run_id is not None
                    and prev_output_dir
                    and config.output_dir != prev_output_dir
                ):
                    self.store.update_run_output_dir(
                        self._run_id, config.output_dir
                    )
            assert config is not None
            self._seed_analysis_units(config)
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
            self._remove_log_handler()
            if self.store is not None and self._run_id is not None:
                try:
                    self.store.finish_run(
                        self._run_id,
                        self.state,
                        self.error,
                        self.ended_at,
                        models_used=list(config.models_used) if config else None,
                        usage_stats=dict(config.usage_stats) if config else None,
                    )
                except Exception as e:
                    logger.warning("Failed to update history database run row: %s", e)
            self.bus.publish(
                {
                    "type": "job",
                    "kind": self.kind,
                    "status": self.state,
                    "error": self.error,
                }
            )

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
                agent_timeout_seconds=DEFAULT_AGENT_TIMEOUT_SECONDS,
            )
            assert self.reporter is not None
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
            self._remove_log_handler()
            self.bus.publish(
                {
                    "type": "job",
                    "kind": self.kind,
                    "status": self.state,
                    "error": self.error,
                }
            )

    def stop(self) -> bool:
        """Cancel the running audit. Returns False if nothing is running."""
        self._reconcile_task_state()
        if self.state not in BUSY_STATES or self._task is None:
            return False
        self.error = ""
        self._task.cancel()
        return True

    def status(self) -> dict:
        self._reconcile_task_state()
        return {
            "kind": self.kind,
            "state": self.state,
            "error": self.error,
            "target": self.config.target if self.config else "",
            "output_dir": self.config.output_dir if self.config else "",
            "started_at": self.started_at,
            "ended_at": self.ended_at,
            "run_id": self._run_id,
            "models_used": list(self.config.models_used) if self.config else [],
            "usage_stats": dict(self.config.usage_stats) if self.config else {},
            "stages": self.reporter.snapshot() if self.reporter else [],
            "reproduction_candidate": self.reproduction_candidate,
            "reproduction_reports": self.reproduction_reports,
        }

    def _install_log_handler(self) -> None:
        self._remove_log_handler()
        handler = WebLogHandler(self.bus)
        handler.setLevel(logging.DEBUG)
        logging.getLogger("code_auditor").addHandler(handler)
        self._log_handler = handler

    def _remove_log_handler(self) -> None:
        if self._log_handler is not None:
            logging.getLogger("code_auditor").removeHandler(self._log_handler)
            self._log_handler = None
