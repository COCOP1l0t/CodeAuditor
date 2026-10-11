from __future__ import annotations

import os
from dataclasses import dataclass

from .config import SandboxMode, SandboxRuntime

_WINDOWS_DOCKER_REASON = (
    "Docker Stage 5 and 6 execution is not supported on native Windows. "
    "Use local-worktree, or run CodeAuditor inside WSL2/Linux for Docker isolation."
)


@dataclass(frozen=True)
class ExecutionCapability:
    available: bool
    reason: str

    def public(self) -> dict[str, object]:
        return {"available": self.available, "reason": self.reason}


def stage56_execution_capability(
    sandbox_mode: SandboxMode,
    sandbox_runtime: SandboxRuntime,
    *,
    platform_name: str | None = None,
) -> ExecutionCapability:
    """Report whether this host may execute the selected Stage 5/6 mode."""
    platform_name = os.name if platform_name is None else platform_name
    if platform_name == "nt":
        if sandbox_mode == "local-worktree":
            return ExecutionCapability(
                True,
                "Runs Stage 5 and 6 in a detached Windows worktree with "
                "Job Object process-tree containment and private artifact files.",
            )
        return ExecutionCapability(False, _WINDOWS_DOCKER_REASON)
    if sandbox_mode == "local-worktree":
        return ExecutionCapability(
            True,
            "Runs Stage 5 and 6 in a detached worktree on the server host "
            "without Docker isolation.",
        )
    runtime_name = {
        "docker-default": "Docker default runtime",
        "runc": "runc",
        "runsc": "gVisor runsc",
    }[sandbox_runtime]
    return ExecutionCapability(True, f"{runtime_name} is supported on this host platform.")


def require_stage56_execution(
    sandbox_mode: SandboxMode,
    sandbox_runtime: SandboxRuntime,
    *,
    platform_name: str | None = None,
) -> None:
    capability = stage56_execution_capability(
        sandbox_mode, sandbox_runtime, platform_name=platform_name
    )
    if not capability.available:
        raise RuntimeError(capability.reason)
