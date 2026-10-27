"""Agent subprocess lifecycle and cross-platform process-tree containment."""

from __future__ import annotations

import asyncio
import contextlib
import os
import signal
from contextvars import ContextVar
from dataclasses import dataclass, field
from typing import Callable, Protocol
from uuid import uuid4

from .logger import get_logger
from .process_supervisor import ProcessJob
from .process_tree import (
    AUDIT_PROCESS_MARKER_ENV,
    CURRENT_AUDIT_PROCESS_MARKER,
    marked_process_ids,
    process_has_marker,
)

logger = get_logger("agent.runtime")

AGENT_PROCESS_MARKER_ENV = "CODE_AUDITOR_AGENT_RUN_ID"
AGENT_PROCESS_TERM_TIMEOUT_SECONDS = 1.0
AGENT_PROCESS_KILL_TIMEOUT_SECONDS = 1.0


class _KillableProcess(Protocol):
    def kill(self) -> object:
        ...


_AGENT_PROCESS_REGISTRAR: ContextVar[Callable[[_KillableProcess | None], None] | None] = ContextVar(
    "agent_process_registrar",
    default=None,
)


@dataclass
class _AgentRunControl:
    processes: list[_KillableProcess] = field(default_factory=list)
    process_job: ProcessJob = field(default_factory=ProcessJob)
    killed_after_status_check: bool = False
    process_marker: str = field(default_factory=lambda: uuid4().hex)

    def register_process(self, process: _KillableProcess | None) -> None:
        if process is None or process in self.processes:
            return
        self.processes.append(process)
        pid = getattr(process, "pid", None)
        if os.name == "nt" and isinstance(pid, int):
            try:
                self.process_job.assign_pid(pid)
            except Exception as exc:
                # A status check can race a process which has already exited.
                # Win32 error 87 means the PID is no longer assignable; there
                # is no descendant tree left to contain in that case.
                if getattr(exc, "args", ()) and exc.args[0] == 87:
                    logger.warning(
                        "Agent process pid=%s exited before Job Object assignment.",
                        pid,
                    )
                    return
                with contextlib.suppress(Exception):
                    process.kill()
                raise

    def kill_processes(self, log_file: str, reason: str) -> None:
        self.killed_after_status_check = True
        if not self.processes:
            logger.warning(
                "Status checker decided the agent has finished, but no agent process was registered to kill: %s. Reason: %s",
                log_file,
                reason,
            )
            return

        for process in list(self.processes):
            pid = getattr(process, "pid", "?")
            logger.warning(
                "Status checker decided the agent has finished; killing agent process pid=%s: %s. Reason: %s",
                pid,
                log_file,
                reason,
            )
            try:
                process.kill()
            except ProcessLookupError:
                pass
            except Exception as exc:
                logger.warning("Failed to kill stale agent process pid=%s: %s", pid, exc)

    def subprocess_env(self) -> dict[str, str]:
        """Environment inherited by the agent CLI and every command it starts."""
        env = {AGENT_PROCESS_MARKER_ENV: self.process_marker}
        audit_marker = CURRENT_AUDIT_PROCESS_MARKER.get()
        if audit_marker:
            env[AUDIT_PROCESS_MARKER_ENV] = audit_marker
        return env

    async def cleanup_processes(self) -> None:
        """Stop all owned agent descendants, including detached children."""
        if os.name == "nt":
            try:
                if self.process_job.pids():
                    self.process_job.terminate()
            finally:
                self.process_job.close()
            return
        pids = _marked_agent_process_ids(self.process_marker)
        if not pids:
            return

        logger.warning(
            "Cleaning up %d process(es) left by agent run %s: %s",
            len(pids),
            self.process_marker[:8],
            ", ".join(str(pid) for pid in pids),
        )
        _signal_marked_agent_processes(self.process_marker, pids, signal.SIGTERM)
        survivors = await _wait_for_marked_agent_processes(
            self.process_marker,
            AGENT_PROCESS_TERM_TIMEOUT_SECONDS,
        )
        if not survivors:
            return

        logger.warning(
            "Agent process(es) ignored SIGTERM; sending SIGKILL: %s",
            ", ".join(str(pid) for pid in survivors),
        )
        _signal_marked_agent_processes(
            self.process_marker,
            survivors,
            signal.SIGKILL,
        )
        survivors = await _wait_for_marked_agent_processes(
            self.process_marker,
            AGENT_PROCESS_KILL_TIMEOUT_SECONDS,
        )
        if survivors:
            logger.error(
                "Agent process cleanup could not stop pid(s): %s",
                ", ".join(str(pid) for pid in survivors),
            )


def _process_has_agent_marker(pid: int, process_marker: str) -> bool:
    """Return whether a live process inherited this exact agent-run marker."""
    return process_has_marker(pid, process_marker, AGENT_PROCESS_MARKER_ENV)


def _marked_agent_process_ids(process_marker: str) -> list[int]:
    """Find same-user descendants even after they have been reparented."""
    return marked_process_ids(process_marker, AGENT_PROCESS_MARKER_ENV)


def _signal_marked_agent_processes(
    process_marker: str,
    pids: list[int],
    sig: signal.Signals,
) -> None:
    for pid in pids:
        # Recheck the marker immediately before signalling so a reused PID can
        # never target an unrelated process.
        if not _process_has_agent_marker(pid, process_marker):
            continue
        try:
            os.kill(pid, sig)
        except (ProcessLookupError, PermissionError):
            pass
        except OSError as exc:
            logger.warning("Failed to signal stale agent process pid=%s: %s", pid, exc)


async def _wait_for_marked_agent_processes(
    process_marker: str,
    timeout_seconds: float,
) -> list[int]:
    deadline = asyncio.get_running_loop().time() + timeout_seconds
    while True:
        survivors = _marked_agent_process_ids(process_marker)
        if not survivors or asyncio.get_running_loop().time() >= deadline:
            return survivors
        await asyncio.sleep(0.05)


def _register_current_agent_process(process: _KillableProcess | None) -> None:
    registrar = _AGENT_PROCESS_REGISTRAR.get()
    if registrar:
        registrar(process)
