"""Docker-backed, per-task scratch workspaces for Stage 5 and Stage 6."""
from __future__ import annotations

import asyncio
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any
from uuid import uuid4

from .config import AuditConfig, AgentBackend
from .logger import get_logger
from .process_tree import current_audit_subprocess_env

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

    def public(self) -> dict[str, Any]:
        return {
            "available": self.available,
            "reason": self.reason,
            "image": self.image,
            "free_bytes": self.free_bytes,
            "minimum_free_bytes": self.minimum_free_bytes,
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

    async def prepare(self, target: str, commit: str) -> DockerScratch:
        self.verify_environment()
        self.root_parent.mkdir(parents=True, exist_ok=True, mode=0o700)
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

    def _verify_runtime(self) -> None:
        _run_checked([self.docker_bin, "version", "--format", "{{.Server.Version}}"])
        try:
            _run_checked([self.docker_bin, "image", "inspect", self.image])
        except DockerSandboxError as exc:
            raise DockerSandboxError(
                f"required sandbox image {self.image!r} is missing; build it with "
                "`docker build -f docker/code-auditor-sandbox.Dockerfile "
                "-t code-auditor-sandbox:latest docker`"
            ) from exc

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
            "schema_version": 1,
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
        }
        # The agent can write every byte below ``root``. Keep the Docker spec
        # and executable wrappers in a sibling control directory so a later
        # repair/status-check invocation cannot be turned into a host-side
        # command or arbitrary bind-mount escape.
        self.spec_path = self.control_dir / "docker-spec.json"
        self.spec_path.write_text(json.dumps(spec, sort_keys=True), encoding="utf-8")
        os.chmod(self.spec_path, 0o600)
        package_root = Path(__file__).resolve().parent.parent
        for tool in ("claude", "codex"):
            wrapper = self.control_dir / tool
            wrapper.write_text(
                f"#!{sys.executable}\n"
                "import sys\n"
                f"sys.path.insert(0, {str(package_root)!r})\n"
                "from code_auditor.sandbox import docker_cli_main\n"
                f"raise SystemExit(docker_cli_main({tool!r}))\n",
                encoding="utf-8",
            )
            wrapper.chmod(0o700)

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
        await asyncio.to_thread(self._remove_containers)
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
            shutil.rmtree(resolved, ignore_errors=False)
        if resolved_control is not None and resolved_control.exists():
            shutil.rmtree(resolved_control, ignore_errors=False)
        self.root = None
        self.control_dir = None

    def _remove_containers(self) -> None:
        # Docker removes ``--rm`` containers asynchronously. A second cleanup
        # racing that removal can report "already in progress" even though the
        # container is about to disappear. Re-scan and retry a few times so a
        # harmless teardown race cannot turn an otherwise successful PoC into
        # a maintenance ``done ⚠`` result.
        last_error: DockerSandboxError | None = None
        for attempt in range(3):
            try:
                ids = _run_checked(
                    [
                        self.docker_bin,
                        "ps",
                        "-aq",
                        "--filter",
                        f"label=code_auditor.scratch_id={self.scratch_id}",
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
                return
            except DockerSandboxError as exc:
                last_error = exc
                message = str(exc).casefold()
                if "already in progress" not in message and "no such container" not in message:
                    break
                if attempt < 2:
                    time.sleep(0.5 * (attempt + 1))
        assert last_error is not None
        raise DockerSandboxError(
            f"cannot remove sandbox container(s) {', '.join(ids)}: {last_error}"
        ) from last_error


def inspect_docker_sandbox_environment(
    backend: AgentBackend,
) -> DockerSandboxCapability:
    """Inspect the server environment used by a selected Agent backend."""
    config = AuditConfig(target=".", output_dir=".", backend=backend)
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
        )
    return DockerSandboxCapability(
        available=True,
        reason=(
            "Docker daemon, sandbox image, scratch storage, and "
            f"{backend} runtime are ready."
        ),
        image=scratch.image,
        free_bytes=free_bytes,
        minimum_free_bytes=scratch.min_free_bytes,
    )


def _load_docker_spec(path: str) -> dict[str, Any]:
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise DockerSandboxError(f"cannot load Docker sandbox spec: {exc}") from exc
    if not isinstance(data, dict) or data.get("schema_version") != 1:
        raise DockerSandboxError("unsupported Docker sandbox spec")
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
        "TMPDIR": str(scratch / "tmp"),
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
                str(spec["image"]),
                "/opt/code-auditor/claude",
                *argv,
            )
        )
    elif tool == "codex":
        command.extend(
            (
                "--mount",
                _docker_mount(str(spec["codex_vendor"]), "/opt/code-auditor/codex", readonly=True),
                str(spec["image"]),
                "/opt/code-auditor/codex/bin/codex",
                *argv,
            )
        )
    else:
        raise DockerSandboxError(f"unsupported Docker agent tool: {tool}")
    return command


def docker_cli_main(tool: str) -> int:
    try:
        command = docker_cli_command(tool, sys.argv[1:], dict(os.environ))
    except DockerSandboxError as exc:
        print(f"CodeAuditor Docker sandbox error: {exc}", file=sys.stderr)
        return 125
    os.execvp(command[0], command)
    return 125
