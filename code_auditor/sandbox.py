"""Docker-backed, per-task scratch workspaces for Stage 5 and Stage 6."""
from __future__ import annotations

import asyncio
import contextlib
import hashlib
import json
import os
import re
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any
from uuid import uuid4

from .config import AuditConfig, AgentBackend, SandboxRuntime, SANDBOX_RUNTIMES
from .logger import get_logger
from .process_tree import current_audit_subprocess_env
from .sandbox_records import (
    create_execution_directory, read_execution_records, write_execution_record,
)

DOCKER_SPEC_ENV = "CODE_AUDITOR_DOCKER_SPEC"
DOCKER_CWD_ENV = "CODE_AUDITOR_DOCKER_CWD"
_SAFE_TASK_RE = re.compile(r"[^a-zA-Z0-9_.-]+")
_FORWARDED_ENV_PREFIXES = (
    "ANTHROPIC_",
    "CLAUDE_",
    "CODEAUDITOR_",
    "CODE_AUDITOR_",
    "OPENAI_",
)
_FORWARDED_ENV_NAMES = frozenset(
    {
        "ALL_PROXY",
        "HTTPS_PROXY",
        "HTTP_PROXY",
        "NO_PROXY",
        "all_proxy",
        "https_proxy",
        "http_proxy",
        "no_proxy",
    }
)

logger = get_logger("sandbox")

_LEGACY_CODEX_PACKAGE_ROOT = Path("/usr/local/lib/node_modules/@openai/codex")


class DockerSandboxError(RuntimeError):
    """Raised when the selected Docker sandbox cannot be prepared."""


@dataclass(frozen=True)
class DockerSandboxCapability:
    """Read-only assessment of whether this server can launch a sandbox."""

    available: bool
    reason: str
    image: str
    free_bytes: int | None
    minimum_free_bytes: int
    requested_runtime: str = "docker-default"
    runtime: str | None = None

    def public(self) -> dict[str, Any]:
        return {
            "available": self.available,
            "reason": self.reason,
            "image": self.image,
            "free_bytes": self.free_bytes,
            "minimum_free_bytes": self.minimum_free_bytes,
            "requested_runtime": self.requested_runtime,
            "runtime": self.runtime,
            "launch_verified": False,
        }


def _safe_task_name(value: str) -> str:
    safe = _SAFE_TASK_RE.sub("-", value).strip("-.")
    return (safe or "task")[:48]


def _require_tmp_root(value: str) -> Path:
    root = Path(value).expanduser().resolve()
    tmp = Path("/tmp").resolve()
    try:
        common = Path(os.path.commonpath((str(root), str(tmp))))
    except ValueError as exc:
        raise DockerSandboxError(f"sandbox root must be under /tmp: {root}") from exc
    if common != tmp or root == tmp:
        raise DockerSandboxError(f"sandbox root must be a dedicated directory under /tmp: {root}")
    if any(char in str(root) for char in (",", "\n", "\r")):
        raise DockerSandboxError(f"sandbox root contains unsupported characters: {root}")
    return root


def _run_checked(command: list[str], *, timeout: int = 30) -> str:
    try:
        completed = subprocess.run(
            command,
            check=True,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=current_audit_subprocess_env(),
        )
    except FileNotFoundError as exc:
        raise DockerSandboxError(f"required executable not found: {command[0]}") from exc
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        output = ""
        if isinstance(exc, subprocess.CalledProcessError):
            output = (exc.stderr or exc.stdout or "").strip()
        raise DockerSandboxError(
            f"sandbox command failed: {' '.join(command)}"
            + (f": {output[-1000:]}" if output else "")
        ) from exc
    return completed.stdout.strip()


def _locate_claude_cli() -> Path:
    try:
        import claude_agent_sdk
    except ImportError as exc:
        raise DockerSandboxError("claude-agent-sdk is not installed") from exc
    path = Path(claude_agent_sdk.__file__).resolve().parent / "_bundled" / "claude"
    if not path.is_file() or not os.access(path, os.X_OK):
        raise DockerSandboxError(f"Claude CLI binary is unavailable: {path}")
    return path


def _locate_codex_vendor() -> Path:
    override = os.environ.get("CODE_AUDITOR_CODEX_VENDOR")
    if override:
        candidates = [Path(override).expanduser()]
    else:
        candidates: list[Path] = []
        codex_bin = os.environ.get("CODE_AUDITOR_CODEX_BIN") or shutil.which("codex")
        if codex_bin:
            resolved_bin = Path(codex_bin).expanduser().resolve()
            package_or_vendor_root = resolved_bin.parent.parent
            if (package_or_vendor_root / "bin" / "codex").resolve() == resolved_bin:
                candidates.append(package_or_vendor_root)
            candidates.extend(
                package_or_vendor_root.glob(
                    "node_modules/@openai/codex-linux-*/vendor/*-unknown-linux-musl"
                )
            )
        candidates.extend(
            _LEGACY_CODEX_PACKAGE_ROOT.glob(
                "node_modules/@openai/codex-linux-*/vendor/*-unknown-linux-musl"
            )
        )
    for candidate in candidates:
        binary = candidate / "bin" / "codex"
        if binary.is_file() and os.access(binary, os.X_OK):
            return candidate.resolve()
    raise DockerSandboxError(
        "Codex static vendor bundle is unavailable; set CODE_AUDITOR_CODEX_VENDOR"
    )


def _atomic_write_text(path: Path, text: str, mode: int) -> None:
    """Write a control file atomically so a concurrent reader/exec sees it whole."""
    fd, temporary = tempfile.mkstemp(
        prefix=f".{path.name}-", dir=path.parent, text=True
    )
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except Exception:
        with contextlib.suppress(OSError):
            os.unlink(temporary)
        raise


def _copy_regular_if_present(source: Path, destination: Path) -> None:
    try:
        source_stat = source.lstat()
    except FileNotFoundError:
        return
    if not stat.S_ISREG(source_stat.st_mode) or stat.S_ISLNK(source_stat.st_mode):
        logger.warning("Skipping unsafe sandbox credential/config path: %s", source)
        return
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, destination, follow_symlinks=False)
    os.chmod(destination, 0o600)


async def _run_async_checked(
    command: list[str],
    *,
    cwd: str | None = None,
    timeout: int = 15 * 60,
) -> str:
    try:
        process = await asyncio.create_subprocess_exec(
            *command,
            cwd=cwd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            env=current_audit_subprocess_env(),
        )
    except FileNotFoundError as exc:
        raise DockerSandboxError(f"required executable not found: {command[0]}") from exc
    try:
        output, _ = await asyncio.wait_for(process.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        process.kill()
        await process.wait()
        raise DockerSandboxError(f"sandbox setup timed out: {' '.join(command)}")
    except asyncio.CancelledError:
        process.kill()
        await process.wait()
        raise
    text = (output or b"").decode("utf-8", errors="replace")
    if process.returncode != 0:
        raise DockerSandboxError(
            f"sandbox setup failed: {' '.join(command)}: {text[-1000:].strip()}"
        )
    return text.strip()


class DockerScratch:
    """One disposable source/build/output tree backed by a Docker write boundary."""

    def __init__(self, config: AuditConfig, task_name: str) -> None:
        self.image = config.sandbox_image
        self.docker_bin = config.sandbox_docker_bin
        self.root_parent = _require_tmp_root(config.sandbox_root)
        self.task_name = _safe_task_name(task_name)
        self.scratch_id = uuid4().hex
        self.root: Path | None = None
        self.control_dir: Path | None = None
        self.source_dir: Path | None = None
        self.input_dir: Path | None = None
        self.artifact_dir: Path | None = None
        self.home_dir: Path | None = None
        self.spec_path: Path | None = None
        self.readonly_mounts: list[Path] = []
        self.backend = config.backend
        self.max_memory = config.sandbox_memory
        self.max_cpus = config.sandbox_cpus
        self.pids_limit = config.sandbox_pids_limit
        self.network_enabled = config.sandbox_network_enabled
        self.min_free_bytes = config.sandbox_min_free_bytes
        if config.sandbox_runtime not in SANDBOX_RUNTIMES:
            raise DockerSandboxError("unsupported sandbox runtime")
        self.requested_runtime = config.sandbox_runtime
        self.runtime: str | None = None
        self.image_id: str | None = None
        self.runtime_version: str | None = None
        self.server_version: str | None = None
        self.host_kernel: str | None = None
        self.architecture: str | None = None
        self.output_dir = config.output_dir
        self.execution_dir: Path | None = None
        self.source_commit = ""
        self.audit_run_id = config.sandbox_run_id
        self.job_key = config.sandbox_job_key

    async def prepare(self, target: str, commit: str) -> DockerScratch:
        self.source_commit = commit
        self.verify_environment()
        self.root_parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self._verify_root_parent()
        root = Path(
            tempfile.mkdtemp(
                prefix=f"{self.task_name}-",
                dir=self.root_parent,
            )
        )
        os.chmod(root, 0o700)
        self.root = root
        try:
            control_dir = Path(
                tempfile.mkdtemp(
                    prefix=f".{self.task_name}-control-",
                    dir=self.root_parent,
                )
            )
        except Exception:
            shutil.rmtree(root)
            self.root = None
            raise
        self.control_dir = control_dir
        try:
            os.chmod(control_dir, 0o700)
            self.execution_dir = create_execution_directory(self.output_dir, self.scratch_id)
            if self.execution_dir.is_relative_to(root):
                raise DockerSandboxError("execution records must be outside the sandbox")
            self.source_dir = root / "source"
            self.input_dir = root / "inputs"
            self.artifact_dir = root / "artifacts"
            self.home_dir = root / "home"
            for directory in (
                self.input_dir,
                self.artifact_dir,
                self.home_dir,
                root / "tmp",
                root / "cache",
            ):
                directory.mkdir(parents=True, mode=0o700)
            await self._prepare_source(target, commit)
            self._prepare_minimal_home()
            self._write_spec_and_wrappers()
        except Exception:
            await self.close()
            raise
        return self

    def _verify_root_parent(self) -> None:
        """Require the shared scratch parent to be a real, owner-only directory.

        The control directory and the host-executed ``claude``/``codex``
        wrappers live directly under this path. A pre-existing directory owned
        by, or writable to, another local user would let that user substitute a
        wrapper and run host commands as the audit user.
        """
        root = self.root_parent
        try:
            info = root.lstat()
        except OSError as exc:
            raise DockerSandboxError(f"sandbox root is unavailable: {root}") from exc
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            raise DockerSandboxError(f"sandbox root must be a real directory: {root}")
        if info.st_uid != os.getuid():
            raise DockerSandboxError(
                f"sandbox root must be owned by the current user: {root}"
            )
        if stat.S_IMODE(info.st_mode) & 0o077:
            os.chmod(root, 0o700)

    def _verify_runtime(self) -> None:
        try:
            info = json.loads(_run_checked([
                self.docker_bin, "info", "--format", "{{json .}}",
            ]))
            runtimes = info["Runtimes"]
            selected = (info["DefaultRuntime"] if self.requested_runtime == "docker-default"
                        else self.requested_runtime)
            if not isinstance(selected, str) or selected not in runtimes:
                raise DockerSandboxError(f"Docker runtime {selected!r} is not registered")
            self.runtime = selected
            self.server_version = info.get("ServerVersion")
            self.host_kernel = info.get("KernelVersion")
            self.architecture = info.get("Architecture")
        except (KeyError, TypeError, ValueError, AttributeError) as exc:
            raise DockerSandboxError("cannot decode Docker runtime information") from exc
        # Version annotations are optional OCI metadata. Their absence must
        # remain unknown rather than being inferred from an unrelated PATH binary.
        try:
            features = runtimes[selected].get("status", {}).get(
                "org.opencontainers.runtime-spec.features", "{}"
            )
            annotations = json.loads(features).get("annotations", {})
            version = annotations.get("org.opencontainers.runc.version")
            self.runtime_version = version.strip() if isinstance(version, str) else None
        except (TypeError, ValueError, AttributeError):
            self.runtime_version = None
        try:
            inspected = json.loads(_run_checked([self.docker_bin, "image", "inspect", self.image]))
            self.image_id = inspected[0]["Id"]
            if not isinstance(self.image_id, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", self.image_id):
                raise ValueError("invalid image id")
        except DockerSandboxError as exc:
            raise DockerSandboxError(
                f"required sandbox image {self.image!r} is missing; build it with "
                "`docker build -f docker/code-auditor-sandbox.Dockerfile "
                "-t code-auditor-sandbox:latest docker`"
            ) from exc
        except (KeyError, IndexError, TypeError, ValueError) as exc:
            raise DockerSandboxError("cannot decode sandbox image identity") from exc

    def verify_environment(self) -> int:
        """Check Docker, image, storage, and backend assets without writing."""
        self._verify_runtime()

        storage_path = self.root_parent
        while not storage_path.exists() and storage_path != storage_path.parent:
            storage_path = storage_path.parent
        if not storage_path.is_dir():
            raise DockerSandboxError(
                f"sandbox storage parent is not a directory: {storage_path}"
            )
        access_path = self.root_parent if self.root_parent.exists() else storage_path
        if self.root_parent.exists() and not self.root_parent.is_dir():
            raise DockerSandboxError(
                f"sandbox root is not a directory: {self.root_parent}"
            )
        if not os.access(access_path, os.W_OK | os.X_OK):
            raise DockerSandboxError(f"sandbox storage is not writable: {access_path}")
        available = shutil.disk_usage(storage_path).free
        if available < self.min_free_bytes:
            raise DockerSandboxError(
                f"sandbox requires at least {self.min_free_bytes} free bytes; "
                f"only {available} are available on {storage_path}"
            )

        if self.backend == "claude":
            _locate_claude_cli()
        elif self.backend == "codex":
            _locate_codex_vendor()
        else:
            raise DockerSandboxError(f"unsupported sandbox backend: {self.backend}")
        return available

    async def _prepare_source(self, target: str, commit: str) -> None:
        assert self.source_dir is not None
        git_dir = Path(target) / ".git"
        if commit and (git_dir.exists() or git_dir.is_file()):
            common_git_dir = _run_checked(
                [
                    "git",
                    "-C",
                    os.path.realpath(target),
                    "rev-parse",
                    "--path-format=absolute",
                    "--git-common-dir",
                ]
            )
            common_git_path = Path(common_git_dir)
            if not common_git_path.is_absolute():
                common_git_path = Path(target, common_git_path)
            common_git_path = common_git_path.resolve()
            if not common_git_path.is_dir():
                raise DockerSandboxError(
                    f"cannot resolve target Git object store: {common_git_path}"
                )
            self.readonly_mounts.append(common_git_path)
            await _run_async_checked(
                [
                    "git",
                    "clone",
                    "--shared",
                    "--no-checkout",
                    "--local",
                    os.path.realpath(target),
                    str(self.source_dir),
                ]
            )
            await _run_async_checked(
                ["git", "checkout", "--detach", commit],
                cwd=str(self.source_dir),
            )
            return
        if not os.path.isdir(target):
            raise DockerSandboxError(f"sandbox target directory is missing: {target}")
        shutil.copytree(target, self.source_dir, symlinks=True)

    def _prepare_minimal_home(self) -> None:
        assert self.home_dir is not None
        host_home = Path.home()
        for source_name, destination_name in (
            (".claude/settings.json", ".claude/settings.json"),
            (".claude/.credentials.json", ".claude/.credentials.json"),
            (".claude.json", ".claude.json"),
            (".codex/auth.json", ".codex/auth.json"),
            (".codex/config.toml", ".codex/config.toml"),
        ):
            _copy_regular_if_present(
                host_home / source_name,
                self.home_dir / destination_name,
            )

    def _write_spec_and_wrappers(self) -> None:
        assert self.root is not None
        assert self.control_dir is not None
        assert self.home_dir is not None
        claude_cli = ""
        codex_vendor = ""
        if self.backend == "claude":
            claude_cli = str(_locate_claude_cli())
        elif self.backend == "codex":
            codex_vendor = str(_locate_codex_vendor())
        else:
            raise DockerSandboxError(f"unsupported sandbox backend: {self.backend}")
        spec = {
            "schema_version": 2,
            "docker_bin": self.docker_bin,
            "image": self.image,
            "scratch_root": str(self.root),
            "scratch_id": self.scratch_id,
            "home": str(self.home_dir),
            "uid": os.getuid(),
            "gid": os.getgid(),
            "network_enabled": self.network_enabled,
            "pids_limit": self.pids_limit,
            "memory": self.max_memory,
            "cpus": self.max_cpus,
            "claude_cli": claude_cli,
            "codex_vendor": codex_vendor,
            "readonly_mounts": [str(path) for path in self.readonly_mounts],
            "requested_runtime": self.requested_runtime,
            "runtime": self.runtime,
            "image_id": self.image_id,
            "runtime_version": self.runtime_version,
            "server_version": self.server_version,
            "host_kernel": self.host_kernel,
            "architecture": self.architecture,
            "source_commit": self.source_commit or None,
            "task_name": self.task_name,
            "audit_run_id": self.audit_run_id,
            "job_key": self.job_key,
            "execution_dir": str(self.execution_dir),
        }
        # The agent can write every byte below ``root``. Keep the Docker spec
        # and executable wrappers in a sibling control directory so a later
        # repair/status-check invocation cannot be turned into a host-side
        # command or arbitrary bind-mount escape.
        self.spec_path = self.control_dir / "docker-spec.json"
        _atomic_write_text(
            self.spec_path, json.dumps(spec, sort_keys=True), 0o600
        )
        package_root = Path(__file__).resolve().parent.parent
        for tool in ("claude", "codex"):
            wrapper = self.control_dir / tool
            _atomic_write_text(
                wrapper,
                f"#!{sys.executable}\n"
                "import sys\n"
                f"sys.path.insert(0, {str(package_root)!r})\n"
                "from code_auditor.sandbox import docker_cli_main\n"
                f"raise SystemExit(docker_cli_main({tool!r}))\n",
                0o700,
            )

    def ensure_backend(self, backend: str) -> None:
        """Prepare this scratch's wrapper metadata for a hot-switched backend."""
        if backend == self.backend:
            return
        previous = self.backend
        self.backend = backend
        try:
            self._write_spec_and_wrappers()
        except Exception:
            self.backend = previous
            raise

    def copy_input(self, source: str | os.PathLike[str], name: str) -> Path:
        assert self.input_dir is not None
        safe_name = _safe_task_name(name)
        destination = self.input_dir / safe_name
        source_path = Path(source)
        source_stat = source_path.lstat()
        if not stat.S_ISREG(source_stat.st_mode) or stat.S_ISLNK(source_stat.st_mode):
            raise DockerSandboxError(f"sandbox input must be a regular file: {source_path}")
        shutil.copyfile(source_path, destination, follow_symlinks=False)
        os.chmod(destination, 0o600)
        return destination

    def copy_input_tree(self, source: str | os.PathLike[str], name: str) -> Path:
        assert self.input_dir is not None
        destination = self.input_dir / _safe_task_name(name)
        shutil.copytree(source, destination, symlinks=True)
        return destination

    def wrapper_path(self, tool: str) -> str:
        if self.control_dir is None or tool not in {"claude", "codex"}:
            raise DockerSandboxError("sandbox wrapper requested before preparation")
        return str(self.control_dir / tool)

    def protected_log_path(self, requested: str) -> str:
        """Map a logical agent log to a host-only, durable file."""
        if self.execution_dir is None:
            raise DockerSandboxError("sandbox log requested before preparation")
        # Hash the logical path without resolving agent-controlled symlinks.
        name = hashlib.sha256(os.path.abspath(requested).encode()).hexdigest()[:24]
        return str(self.execution_dir / f"agent-{name}.log")

    async def cleanup_invocation(self, agent_run_id: str, outcome: str) -> None:
        """Clean one invocation without stopping a concurrent status checker."""
        try:
            await asyncio.to_thread(self._remove_containers, agent_run_id)
        except Exception:
            self._finalize_records(agent_run_id, outcome, "failed")
            raise
        self._finalize_records(agent_run_id, outcome, "verified")

    def _finalize_records(self, agent_run_id: str | None, outcome: str, cleanup: str) -> None:
        if self.execution_dir is None:
            return
        for record in read_execution_records(self.execution_dir):
            if agent_run_id is not None and record.get("agent_run_id") != agent_run_id:
                continue
            record["cleanup"] = cleanup
            interrupted = record.get("state") in {"pending", "created", "starting", "running"}
            if interrupted:
                record["state"] = "interrupted"
                record["ended_at"] = time.time()
            if agent_run_id is not None or interrupted:
                record["invocation_outcome"] = outcome
            write_execution_record(self.execution_dir, record)

    def wrapper_env(self, cwd: str) -> dict[str, str]:
        if self.spec_path is None or self.root is None:
            raise DockerSandboxError("sandbox environment requested before preparation")
        resolved_cwd = Path(cwd).resolve()
        if Path(os.path.commonpath((str(resolved_cwd), str(self.root)))) != self.root:
            raise DockerSandboxError(f"sandbox cwd escapes scratch root: {resolved_cwd}")
        return {
            DOCKER_SPEC_ENV: str(self.spec_path),
            DOCKER_CWD_ENV: str(resolved_cwd),
        }

    def audit_config(self, config: AuditConfig) -> AuditConfig:
        assert self.source_dir is not None
        assert self.artifact_dir is not None
        return replace(
            config,
            target=str(self.source_dir),
            output_dir=str(self.artifact_dir),
            wiki_path=None,
            poc_worktree=str(self.source_dir),
            agent_settings_source=config.agent_settings_source or config,
        )

    async def close(self) -> None:
        if self.root is None:
            return
        try:
            await asyncio.to_thread(self._remove_containers)
        except Exception:
            self._finalize_records(None, "task_cleanup_failed", "failed")
            raise
        self._finalize_records(None, "task_closed", "verified")
        root = self.root
        control_dir = self.control_dir
        resolved = root.resolve()
        parent = self.root_parent.resolve()
        if resolved.parent != parent or not resolved.name.startswith(f"{self.task_name}-"):
            raise DockerSandboxError(f"refusing to remove unexpected sandbox path: {resolved}")
        if control_dir is not None:
            resolved_control = control_dir.resolve()
            if (
                resolved_control.parent != parent
                or not resolved_control.name.startswith(
                    f".{self.task_name}-control-"
                )
            ):
                raise DockerSandboxError(
                    f"refusing to remove unexpected sandbox control path: {resolved_control}"
                )
        else:
            resolved_control = None
        if resolved.exists():
            _make_tree_removable(resolved)
            shutil.rmtree(resolved, ignore_errors=False)
        if resolved_control is not None and resolved_control.exists():
            _make_tree_removable(resolved_control)
            shutil.rmtree(resolved_control, ignore_errors=False)
        self.root = None
        self.control_dir = None

    def _remove_containers(self, agent_run_id: str | None = None) -> None:
        # Docker removes ``--rm`` containers asynchronously. A second cleanup
        # racing that removal can report "already in progress" even though the
        # container is about to disappear. Re-scan and retry a few times so a
        # harmless teardown race cannot turn an otherwise successful PoC into
        # a maintenance ``done ⚠`` result.
        last_error: DockerSandboxError | None = None
        for attempt in range(4):
            try:
                ids = _run_checked(
                    [
                        self.docker_bin,
                        "ps",
                        "-aq",
                        "--filter",
                        f"label=code_auditor.scratch_id={self.scratch_id}",
                        *(["--filter", f"label=code_auditor.agent_run_id={agent_run_id}"]
                          if agent_run_id is not None else []),
                    ],
                    timeout=15,
                ).split()
            except DockerSandboxError as exc:
                raise DockerSandboxError(
                    f"cannot verify sandbox container cleanup: {exc}"
                ) from exc
            if not ids:
                return
            try:
                _run_checked([self.docker_bin, "rm", "-f", *ids], timeout=30)
                # A successful rm must be followed by an empty scan.
                last_error = DockerSandboxError("containers remain after removal")
            except DockerSandboxError as exc:
                last_error = exc
                message = str(exc).casefold()
                if "already in progress" not in message and "no such container" not in message:
                    break
            if attempt < 3:
                time.sleep(0.2 * (attempt + 1))
        assert last_error is not None
        raise DockerSandboxError(
            f"sandbox container cleanup could not be verified for {', '.join(ids)}: {last_error}"
        ) from last_error


def inspect_docker_sandbox_environment(
    backend: AgentBackend,
    runtime: SandboxRuntime = "docker-default",
) -> DockerSandboxCapability:
    """Inspect the server environment used by a selected Agent backend."""
    config = AuditConfig(target=".", output_dir=".", backend=backend, sandbox_runtime=runtime)
    try:
        scratch = DockerScratch(config, "capability-check")
        free_bytes = scratch.verify_environment()
    except (DockerSandboxError, OSError) as exc:
        return DockerSandboxCapability(
            available=False,
            reason=str(exc),
            image=config.sandbox_image,
            free_bytes=None,
            minimum_free_bytes=config.sandbox_min_free_bytes,
            requested_runtime=runtime,
        )
    return DockerSandboxCapability(
        available=True,
        reason=(
            "Docker daemon, sandbox image, scratch storage, and "
            f"{backend} assets are available; container launch has not been tested."
        ),
        image=scratch.image,
        free_bytes=free_bytes,
        minimum_free_bytes=scratch.min_free_bytes,
        requested_runtime=runtime,
        runtime=scratch.runtime,
    )


def _load_docker_spec(path: str) -> dict[str, Any]:
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise DockerSandboxError(f"cannot load Docker sandbox spec: {exc}") from exc
    if not isinstance(data, dict) or data.get("schema_version") not in {1, 2}:
        raise DockerSandboxError("unsupported Docker sandbox spec")
    if data["schema_version"] == 2:
        if not data.get("runtime") or not data.get("image_id") or not data.get("execution_dir"):
            raise DockerSandboxError("sandbox runtime and image must be resolved before launch")
    return data


def _docker_mount(source: str, destination: str, *, readonly: bool = False) -> str:
    if any(char in source + destination for char in (",", "\n", "\r")):
        raise DockerSandboxError("Docker mount path contains unsupported characters")
    value = f"type=bind,src={source},dst={destination}"
    return value + (",readonly" if readonly else "")


def _container_name(spec: dict[str, Any], tool: str) -> str:
    marker = os.environ.get("CODE_AUDITOR_AGENT_RUN_ID", uuid4().hex)
    nonce = uuid4().hex[:6]
    return f"code-auditor-{str(spec['scratch_id'])[:10]}-{marker[:10]}-{tool}-{nonce}"


def _make_tree_removable(root: Path) -> None:
    """Restore directory write/execute bits before deleting a scratch tree.

    Go's module cache deliberately removes write bits from extracted module
    directories.  The scratch tree is disposable and bounded by ``root``;
    restoring only directory owner bits lets ``shutil.rmtree`` unlink those
    files without making any files outside the scratch writable.
    """
    if not root.exists():
        return
    for current, directories, _files in os.walk(root, topdown=False, followlinks=False):
        paths = [Path(current), *(Path(current) / name for name in directories)]
        for path in paths:
            try:
                info = path.lstat()
            except FileNotFoundError:
                continue
            if stat.S_ISDIR(info.st_mode):
                os.chmod(path, stat.S_IMODE(info.st_mode) | stat.S_IRWXU)


def docker_cli_command(tool: str, argv: list[str], environ: dict[str, str]) -> list[str]:
    """Build the Docker CLI command used by an SDK wrapper."""
    spec_path = environ.get(DOCKER_SPEC_ENV, "")
    cwd = Path(environ.get(DOCKER_CWD_ENV, "")).resolve()
    spec = _load_docker_spec(spec_path)
    scratch = Path(str(spec["scratch_root"])).resolve()
    if Path(os.path.commonpath((str(cwd), str(scratch)))) != scratch:
        raise DockerSandboxError(f"Docker wrapper cwd escapes scratch root: {cwd}")
    command = [
        str(spec["docker_bin"]),
        "run",
        "--rm",
        "--interactive",
        "--init",
        "--name",
        _container_name(spec, tool),
        "--label",
        f"code_auditor.scratch_id={spec['scratch_id']}",
        "--label",
        f"code_auditor.agent_run_id={environ.get('CODE_AUDITOR_AGENT_RUN_ID', '')}",
        "--read-only",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        f"--pids-limit={int(spec['pids_limit'])}",
        f"--memory={spec['memory']}",
        f"--cpus={spec['cpus']}",
        f"--user={int(spec['uid'])}:{int(spec['gid'])}",
        "--workdir",
        str(cwd),
        "--mount",
        _docker_mount(str(scratch), str(scratch)),
        "--tmpfs",
        "/tmp:rw,nosuid,nodev,size=512m,mode=1777",
        "--network",
        "bridge" if spec.get("network_enabled") else "none",
    ]
    if spec.get("runtime"):
        command.extend(("--runtime", str(spec["runtime"])))
    readonly_mounts = spec.get("readonly_mounts", [])
    if not isinstance(readonly_mounts, list):
        raise DockerSandboxError("Docker sandbox readonly_mounts must be a list")
    for value in readonly_mounts:
        mount_path = Path(str(value)).resolve()
        if not mount_path.exists():
            raise DockerSandboxError(
                f"Docker sandbox read-only mount is missing: {mount_path}"
            )
        command.extend(
            (
                "--mount",
                _docker_mount(str(mount_path), str(mount_path), readonly=True),
            )
        )
    runtime_env = {
        "HOME": str(spec["home"]),
        "USER": "code-auditor",
        # Keep tools installed by a PoC inside the disposable scratch tree and
        # make them immediately invokable.  The host PATH is intentionally not
        # forwarded into the container.
        "GOBIN": str(scratch / "home" / "go" / "bin"),
        "PATH": (
            f"{scratch / 'home' / 'go' / 'bin'}:/usr/local/sbin:/usr/local/bin:"
            "/usr/sbin:/usr/bin:/sbin:/bin"
        ),
        "TMPDIR": str(scratch / "tmp"),
        "CODE_AUDITOR_SCRATCH_ROOT": str(scratch),
        "CODE_AUDITOR_ARTIFACT_DIR": str(scratch / "artifacts"),
        "XDG_CACHE_HOME": str(scratch / "cache" / "xdg"),
        "CARGO_HOME": str(scratch / "cache" / "cargo-home"),
        "CARGO_TARGET_DIR": str(scratch / "cache" / "cargo-target"),
        "GOCACHE": str(scratch / "cache" / "go-build"),
        "GOMODCACHE": str(scratch / "cache" / "go-mod"),
        "PIP_CACHE_DIR": str(scratch / "cache" / "pip"),
        "npm_config_cache": str(scratch / "cache" / "npm"),
        "GRADLE_USER_HOME": str(scratch / "cache" / "gradle"),
        "CCACHE_DIR": str(scratch / "cache" / "ccache"),
        "GIT_OPTIONAL_LOCKS": "0",
    }
    for name, value in runtime_env.items():
        command.extend(("--env", f"{name}={value}"))
    for name in sorted(environ):
        if name in runtime_env or name in {DOCKER_SPEC_ENV, DOCKER_CWD_ENV}:
            continue
        if (
            name not in _FORWARDED_ENV_NAMES
            and not name.startswith(_FORWARDED_ENV_PREFIXES)
        ):
            continue
        command.extend(("--env", name))

    if tool == "claude":
        command.extend(
            (
                "--mount",
                _docker_mount(str(spec["claude_cli"]), "/opt/code-auditor/claude", readonly=True),
                str(spec.get("image_id") or spec["image"]),
                "/opt/code-auditor/claude",
                *argv,
            )
        )
    elif tool == "codex":
        command.extend(
            (
                "--mount",
                _docker_mount(str(spec["codex_vendor"]), "/opt/code-auditor/codex", readonly=True),
                str(spec.get("image_id") or spec["image"]),
                "/opt/code-auditor/codex/bin/codex",
                *argv,
            )
        )
    else:
        raise DockerSandboxError(f"unsupported Docker agent tool: {tool}")
    return command


def _inspect_container(docker_bin: str, container: str) -> dict[str, Any]:
    try:
        result = json.loads(_run_checked([docker_bin, "inspect", container]))
        if not isinstance(result, list) or len(result) != 1 or not isinstance(result[0], dict):
            raise ValueError("unexpected inspect result")
        return result[0]
    except (ValueError, TypeError) as exc:
        raise DockerSandboxError("cannot decode container state") from exc


def _supervise_container(command: list[str], spec: dict[str, Any], tool: str) -> int:
    """Create, inspect, attach, and remove a single container on the host.

    Keep a durable record before creating anything. The parent can finish
    cleanup using labels even if this supervisor is killed with SIGKILL.
    """
    directory = Path(spec["execution_dir"])
    docker_bin = command[0]
    name = command[command.index("--name") + 1]
    marker = os.environ.get("CODE_AUDITOR_AGENT_RUN_ID", "")
    record = {
        "schema_version": 1,
        "execution_id": uuid4().hex,
        "scratch_id": spec["scratch_id"],
        "agent_run_id": marker,
        "task_name": spec["task_name"],
        "audit_run_id": spec.get("audit_run_id"),
        "job_key": spec.get("job_key"),
        "backend": tool,
        "source_commit": spec.get("source_commit"),
        "requested_runtime": spec["requested_runtime"],
        "runtime": None,
        "configured_runtime": spec["runtime"],
        "runtime_version": spec.get("runtime_version"),
        "docker_version": spec.get("server_version"),
        "host_kernel": spec.get("host_kernel"),
        "architecture": spec.get("architecture"),
        "requested_image": spec["image"],
        "image_id": None,
        "network": "bridge" if spec["network_enabled"] else "none",
        "limits": {"memory": spec["memory"], "cpus": spec["cpus"],
                   "pids": spec["pids_limit"]},
        "container_name": name,
        "container_id": None,
        "started_at": time.time(),
        "ended_at": None,
        "exit_code": None,
        "oom_killed": None,
        "state": "pending",
        "cleanup": "pending",
    }
    write_execution_record(directory, record)
    attached: subprocess.Popen | None = None
    exit_code = 125
    phase = "create"
    previous_handlers = {}

    def interrupted(signum: int, _frame: Any) -> None:
        raise SystemExit(128 + signum)

    try:
        for signum in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
            previous_handlers[signum] = signal.signal(signum, interrupted)
        create_command = [docker_bin, "create", *command[3:]]
        container_id = _run_checked(create_command, timeout=60)
        record["container_id"] = container_id
        record["state"] = "created"
        phase = "inspect"
        inspected = _inspect_container(docker_bin, container_id)
        record["runtime"] = inspected["HostConfig"]["Runtime"]
        record["image_id"] = inspected["Image"]
        host_config = inspected["HostConfig"]
        record["effective_limits"] = {
            "memory_bytes": host_config.get("Memory"),
            "nano_cpus": host_config.get("NanoCpus"),
            "pids": host_config.get("PidsLimit"),
        }
        record["effective_network"] = host_config.get("NetworkMode")
        record["security"] = {
            "read_only_rootfs": host_config.get("ReadonlyRootfs"),
            "cap_drop": host_config.get("CapDrop"),
            "security_options": host_config.get("SecurityOpt"),
            "user": inspected.get("Config", {}).get("User"),
        }
        if record["runtime"] != spec["runtime"] or record["image_id"] != spec["image_id"]:
            raise DockerSandboxError("container runtime or image does not match the pinned configuration")
        write_execution_record(directory, record)
        phase = "start"
        attached = subprocess.Popen([docker_bin, "start", "--attach", "--interactive", container_id])
        record["state"] = "starting"
        write_execution_record(directory, record)
        attached.wait()
        phase = "exit inspection"
        state = _inspect_container(docker_bin, container_id)["State"]
        if state.get("Status") != "exited":
            raise DockerSandboxError("container attach ended without a confirmed container exit")
        record["exit_code"] = int(state["ExitCode"])
        record["oom_killed"] = bool(state.get("OOMKilled", False))
        record["state"] = "exited"
        exit_code = record["exit_code"]
    except SystemExit as exc:
        record["state"] = "interrupted"
        exit_code = int(exc.code or 125)
    except (DockerSandboxError, OSError, KeyError, TypeError, ValueError) as exc:
        record["state"] = "failed"
        record["failure_phase"] = phase
        # Error text is sent to the SDK, but never persisted as environment
        # metadata, since commands and daemon errors can contain secrets.
        print(f"CodeAuditor sandbox {phase} failed: {exc}", file=sys.stderr)
    finally:
        # Let the parent perform label-based cleanup if we receive a second
        # termination signal while removing the container.
        for signum in previous_handlers:
            signal.signal(signum, signal.SIG_IGN)
        try:
            if attached is not None and attached.poll() is None:
                attached.terminate()
                try:
                    attached.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    attached.kill()
                    attached.wait()
            # This query also handles a create request which reached Docker
            # even though its client failed before returning the container ID.
            # Scope by container name as well as labels: retries of one SDK
            # invocation must not remove a later container with the same marker.
            _remove_named_container(docker_bin, name, str(spec["scratch_id"]), marker)
            record["cleanup"] = "verified"
        except (DockerSandboxError, OSError) as exc:
            record["cleanup"] = "failed"
            exit_code = 125
            print(f"CodeAuditor sandbox cleanup failed: {exc}", file=sys.stderr)
        finally:
            record["ended_at"] = time.time()
            write_execution_record(directory, record)
            for signum, handler in previous_handlers.items():
                signal.signal(signum, handler)
    return exit_code


def _remove_named_container(docker_bin: str, name: str, scratch_id: str, marker: str) -> None:
    for attempt in range(4):
        ids = _run_checked([
            docker_bin, "ps", "-aq", "--filter", f"name=^/{name}$",
            "--filter", f"label=code_auditor.scratch_id={scratch_id}",
            "--filter", f"label=code_auditor.agent_run_id={marker}",
        ], timeout=15).split()
        if not ids:
            return
        try:
            _run_checked([docker_bin, "rm", "-f", *ids], timeout=30)
        except DockerSandboxError as exc:
            if not any(token in str(exc).casefold() for token in ("already in progress", "no such container")):
                raise
        if attempt < 3:
            time.sleep(0.2 * (attempt + 1))
    raise DockerSandboxError("cannot verify container removal")


def docker_cli_main(tool: str) -> int:
    try:
        command = docker_cli_command(tool, sys.argv[1:], dict(os.environ))
        spec = _load_docker_spec(os.environ[DOCKER_SPEC_ENV])
        if spec["schema_version"] == 2:
            return _supervise_container(command, spec, tool)
    except DockerSandboxError as exc:
        print(f"CodeAuditor Docker sandbox error: {exc}", file=sys.stderr)
        return 125
    # Preserve already-running workers whose protected wrappers use a v1 spec.
    # Newly prepared tasks always use the inspected, recorded v2 lifecycle.
    os.execvp(command[0], command)
    return 125
