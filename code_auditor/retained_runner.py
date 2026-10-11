from __future__ import annotations

import asyncio
import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from .process_supervisor import ProcessJob
from .retention import RetainManifest, load_retain_manifest


class RetainedRunnerError(RuntimeError):
    pass


@dataclass(frozen=True)
class RetainedRunResult:
    returncode: int
    output: str


def retained_entrypoint_command(root: Path, manifest: RetainManifest) -> list[str]:
    entrypoint = str(root / manifest.entrypoint)
    if manifest.platform == "windows" and manifest.interpreter == "powershell":
        shell = shutil.which("pwsh.exe") or shutil.which("powershell.exe")
        if shell is None:
            raise RetainedRunnerError("PowerShell is not available on this server")
        return [
            shell,
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            entrypoint,
            *manifest.argv,
        ]
    if manifest.platform == "linux" and manifest.interpreter == "sh":
        shell = "/bin/sh"
        if not os.path.isfile(shell):
            raise RetainedRunnerError("/bin/sh is not available on this server")
        return [shell, entrypoint, *manifest.argv]
    raise RetainedRunnerError("retained entrypoint is not executable on this host")


async def run_retained_entrypoint(
    artifact_dir: str | os.PathLike[str], *, timeout_seconds: float = 300
) -> RetainedRunResult:
    root = Path(artifact_dir).resolve()
    manifest = load_retain_manifest(root)
    expected_platform = "windows" if os.name == "nt" else "linux"
    if manifest.platform != expected_platform:
        raise RetainedRunnerError(
            f"retained entrypoint targets {manifest.platform}, not {expected_platform}"
        )
    # Re-load immediately before spawn so file sizes and hashes are checked at
    # the execution boundary rather than trusted from an earlier UI request.
    manifest = load_retain_manifest(root)
    command = retained_entrypoint_command(root, manifest)
    env = {
        key: value
        for key, value in os.environ.items()
        if key.upper() in {"PATH", "SYSTEMROOT", "WINDIR", "TEMP", "TMP", "COMSPEC"}
    }
    process_job = ProcessJob()
    proc = await asyncio.create_subprocess_exec(
        *command,
        cwd=root,
        env=env,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
        start_new_session=os.name != "nt",
        creationflags=(
            subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0
        ),
    )
    process_job.assign_pid(proc.pid)
    try:
        try:
            output, _ = await asyncio.wait_for(proc.communicate(), timeout_seconds)
        except (TimeoutError, asyncio.CancelledError):
            process_job.terminate()
            await proc.wait()
            raise
    finally:
        process_job.close()
    return RetainedRunResult(
        returncode=int(proc.returncode or 0),
        output=(output or b"").decode("utf-8", errors="replace"),
    )
