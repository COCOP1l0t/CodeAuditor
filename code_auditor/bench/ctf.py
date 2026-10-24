"""Shared plumbing for local, file-based CTF benchmarks.

CTFTiny and CyBench differ in metadata layout but share the same shape: a
checked-out dataset, a small set of handout files per task, an optional Docker
Compose server, and an exact flag comparison. Keeping that plumbing here stops
each adapter from re-implementing (and accidentally weakening) the two safety
rules that matter:

* only an explicit allowlist of handout files reaches the agent workspace;
* the ground-truth flag must not be present anywhere in that workspace.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterable, Sequence

from .base import Outcome, Submission
from ..logger import get_logger

logger = get_logger("bench.ctf")

DEFAULT_COMPOSE_NETWORK = "ctfnet"
DEFAULT_COMMAND_TIMEOUT_SECONDS = 180.0
_SCAN_CHUNK = 1024 * 1024
_SAFE_COMPONENT = re.compile(r"[^A-Za-z0-9._-]+")


class CTFWorkspaceError(RuntimeError):
    """A local CTF workspace or its services could not be prepared safely."""


def safe_component(value: str, *, limit: int = 80) -> str:
    """Lower-case path/container-safe token for an instance id or project name."""
    cleaned = _SAFE_COMPONENT.sub("_", value.strip().lower()).strip("._-")
    return (cleaned[:limit] or "instance")


def normalize_flag(value: str) -> str:
    """The only normalization both benchmarks' harnesses apply: outer whitespace."""
    return value.strip()


def grade_flag(
    instance_id: str,
    submission: Submission,
    expected: str,
    *,
    score: float = 0.0,
    detail: dict | None = None,
) -> Outcome:
    """Compare a submitted flag exactly, never guessing on either side."""
    if submission.kind != "flag":
        raise ValueError("Local CTF adapters only accept kind='flag' submissions.")
    if submission.instance_id and submission.instance_id != instance_id:
        raise ValueError("submission.instance_id does not match the graded instance.")
    submitted = normalize_flag(submission.value)
    wanted = normalize_flag(expected)
    if not submitted:
        return Outcome(
            instance_id=instance_id,
            success=False,
            detail={"error": "empty flag", **(detail or {})},
        )
    matched = bool(wanted) and submitted == wanted
    return Outcome(
        instance_id=instance_id,
        success=matched,
        score=float(score) if matched else 0.0,
        detail={
            "matched": matched,
            "submitted_length": len(submitted),
            **(detail or {}),
        },
    )


@dataclass(frozen=True)
class CommandResult:
    args: tuple[str, ...]
    cwd: Path | None
    returncode: int
    stdout: str = ""
    stderr: str = ""

    @property
    def ok(self) -> bool:
        return self.returncode == 0


CommandRunner = Callable[[Sequence[str], Path | None], CommandResult]


def run_command(
    args: Sequence[str],
    cwd: Path | None,
    *,
    timeout: float = DEFAULT_COMMAND_TIMEOUT_SECONDS,
) -> CommandResult:
    """Run an argv list without a shell; never raises for a non-zero exit."""
    argv = tuple(str(part) for part in args)
    try:
        completed = subprocess.run(
            argv,
            cwd=str(cwd) if cwd is not None else None,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        return CommandResult(argv, cwd, completed.returncode, completed.stdout, completed.stderr)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return CommandResult(argv, cwd, 127, "", str(exc))


class LocalCTFWorkspace:
    """One agent-visible working directory built from an allowlist."""

    def __init__(
        self,
        workdir: Path,
        challenge_dir: Path,
        allowed_files: Iterable[str],
    ) -> None:
        self.workdir = Path(workdir)
        self.challenge_dir = Path(challenge_dir)
        self.allowed_files = tuple(str(name) for name in allowed_files if str(name))

    def materialize(self) -> Path:
        """Copy only the listed handout paths, rejecting traversal and symlinks."""
        if self.workdir.exists():
            shutil.rmtree(self.workdir)
        self.workdir.mkdir(parents=True, exist_ok=True)
        root = self.challenge_dir.resolve()
        for name in self.allowed_files:
            relative = Path(name)
            if relative.is_absolute() or ".." in relative.parts:
                raise CTFWorkspaceError(f"Refusing an absolute or escaping handout: {name}")
            source = (self.challenge_dir / relative)
            try:
                resolved = source.resolve()
                resolved.relative_to(root)
            except (OSError, ValueError) as exc:
                raise CTFWorkspaceError(
                    f"Handout {name} resolves outside the challenge directory."
                ) from exc
            if not resolved.exists():
                raise CTFWorkspaceError(f"Missing handout: {name}")
            target = self.workdir / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            if resolved.is_dir():
                # Preserve symlinks so the workspace scan can reject them; a
                # follow-links copy could silently pull in an out-of-tree file.
                shutil.copytree(resolved, target, symlinks=True)
            else:
                shutil.copy2(resolved, target)
        return self.workdir

    def assert_no_ground_truth(self, flag: str) -> None:
        """Fail if the exact flag bytes appear anywhere in the workspace."""
        needle = normalize_flag(flag).encode("utf-8")
        if not needle:
            raise CTFWorkspaceError("Refusing to prepare a challenge without a known flag.")
        if not self.workdir.is_dir():
            raise CTFWorkspaceError("Workspace must be materialized before scanning it.")
        for path in self.workdir.rglob("*"):
            if path.is_symlink():
                raise CTFWorkspaceError(f"Workspace contains a symlink: {path}")
            if not path.is_file():
                continue
            if _file_contains(path, needle):
                raise CTFWorkspaceError(
                    f"Ground-truth flag would be visible to the agent in {path.name}."
                )

    def cleanup(self) -> None:
        if self.workdir.exists():
            shutil.rmtree(self.workdir, ignore_errors=True)


def _file_contains(path: Path, needle: bytes) -> bool:
    try:
        with path.open("rb") as handle:
            overlap = b""
            while True:
                chunk = handle.read(_SCAN_CHUNK)
                if not chunk:
                    return False
                if needle in overlap + chunk:
                    return True
                overlap = chunk[-(len(needle) - 1):] if len(needle) > 1 else b""
    except OSError:
        return False


@dataclass
class ComposeProject:
    """Lifecycle of one task's Docker Compose stack (host-side)."""

    project: str
    directory: Path
    runner: CommandRunner = run_command
    network: str = DEFAULT_COMPOSE_NETWORK
    services: list[str] = field(default_factory=list, init=False)

    def _compose(self, *args: str) -> CommandResult:
        return self.runner(
            ("docker", "compose", "-p", self.project, *args), self.directory
        )

    def ensure_network(self) -> None:
        result = self.runner(("docker", "network", "create", self.network), None)
        if not result.ok and "already exists" not in (result.stderr + result.stdout).lower():
            raise CTFWorkspaceError(
                f"Could not create Docker network {self.network}: "
                f"{result.stderr.strip()[:300]}"
            )

    def up(self) -> None:
        self.ensure_network()
        result = self._compose("up", "-d")
        if not result.ok:
            raise CTFWorkspaceError(
                f"docker compose up failed for {self.project}: "
                f"{result.stderr.strip()[:500]}"
            )

    def host_port(self, internal_port: int | None) -> int | None:
        if not internal_port:
            return None
        services = self._compose("config", "--services")
        if services.ok:
            self.services = [line.strip() for line in services.stdout.splitlines() if line.strip()]
        for service in self.services:
            result = self._compose("port", service, str(internal_port))
            if result.ok and result.stdout.strip():
                published = result.stdout.strip().splitlines()[0].strip()
                try:
                    return int(published.rsplit(":", 1)[-1])
                except ValueError:
                    continue
        return None

    def down(self) -> None:
        result = self._compose("down", "-v", "--remove-orphans")
        if not result.ok:
            logger.warning(
                "docker compose down failed for %s: %s",
                self.project,
                result.stderr.strip()[:300],
            )


def default_work_root() -> Path:
    return Path(tempfile.gettempdir()) / "code-auditor-bench"


def ensure_work_root(path: str | Path | None, suffix: str) -> Path:
    root = Path(path) if path is not None else default_work_root() / suffix
    root.mkdir(parents=True, exist_ok=True)
    return root
