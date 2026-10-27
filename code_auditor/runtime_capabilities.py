from __future__ import annotations

import os
import sys
from dataclasses import dataclass

from .config import SandboxMode, SandboxRuntime

_WINDOWS_DOCKER_REASON = (
    "Docker Stage 5 and 6 execution is not supported on native Windows. "
    "Use local-worktree, or run CodeAuditor inside WSL2/Linux for Docker isolation."
)
_MACOS_DOCKER_REASON = (
    "Docker Stage 5 and 6 execution is not supported on native macOS because "
    "the sandbox mounts Linux Agent binaries into a Linux container. Use "
    "local-worktree, or run CodeAuditor inside a Linux VM/container."
)


def current_platform_name() -> str:
    if os.name == "nt":
        return "windows"
    if sys.platform == "darwin":
        return "macos"
    return "linux"


def _normalize_platform_name(platform_name: str) -> str:
    return {
        "nt": "windows",
        "win32": "windows",
        "darwin": "macos",
        "posix": "linux",
    }.get(platform_name, platform_name)


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
    platform_name = _normalize_platform_name(
        current_platform_name() if platform_name is None else platform_name
    )
    if platform_name == "windows":
        if sandbox_mode == "local-worktree":
            return ExecutionCapability(
                True,
                "Runs Stage 5 and 6 in a detached Windows worktree with "
                "Job Object process-tree containment and private artifact files.",
            )
        return ExecutionCapability(False, _WINDOWS_DOCKER_REASON)
    if platform_name == "macos":
        if sandbox_mode == "local-worktree":
            return ExecutionCapability(
                True,
                "Runs Stage 5 and 6 in a detached macOS worktree on the server "
                "host without Docker isolation.",
            )
        return ExecutionCapability(False, _MACOS_DOCKER_REASON)
    if platform_name != "linux":
        return ExecutionCapability(
            False, f"Stage 5 and 6 execution is not supported on {platform_name!r}."
        )
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
