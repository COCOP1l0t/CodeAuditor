"""Git repository acquisition for audit targets.

A git URL (HTTPS or scp-like SSH) is mirrored into a long-term local
checkout under ``~/.code_auditor/repo/`` (default, see
:data:`DEFAULT_REPOS_DIR`). The mirror path preserves host/owner/repo so
same-named repositories from different origins never collide. Existing
checkouts are reused as-is — stage 0 of the audit pipeline already runs
``git pull`` on the target before auditing.
"""
from __future__ import annotations

import asyncio
import ipaddress
import os
import re
import subprocess
import urllib.parse
from datetime import datetime

from .logger import get_logger

logger = get_logger("repos")

DEFAULT_REPOS_DIR = os.path.join("~", ".code_auditor", "repo")
DEFAULT_RESULTS_DIR = os.path.join("~", ".code_auditor", "results")

_SCP_LIKE_RE = re.compile(r"^[\w.-]+@(?P<host>[\w.-]+):(?P<path>.+)$")
_SAFE_SEGMENT_RE = re.compile(r"^[\w.-]+$")
_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$"
)


class RepoError(Exception):
    """Raised when a repository URL cannot be resolved or cloned."""


def validate_remote_repo_url(url: str) -> str:
    """Validate a web-submitted remote Git URL.

    Web jobs accept only HTTPS and Git-over-SSH URLs. Local paths, file URLs,
    helper protocols, credentials in HTTPS URLs, control characters, and
    loopback/private IP literals are rejected before ``git clone`` is invoked.
    """
    if not isinstance(url, str):
        raise RepoError("Git repository URL must be a string.")
    normalized = url.strip()
    if not normalized or len(normalized) > 2048:
        raise RepoError("Git repository URL must be between 1 and 2048 characters.")
    if any(char.isspace() or ord(char) < 32 for char in normalized):
        raise RepoError("Git repository URL cannot contain whitespace or controls.")

    scp_match = _SCP_LIKE_RE.fullmatch(normalized)
    if scp_match and "://" not in normalized:
        username = normalized.split("@", 1)[0]
        if username != "git":
            raise RepoError("SSH Git URLs must use the 'git' user.")
        host = scp_match.group("host")
    else:
        parsed = urllib.parse.urlparse(normalized)
        if parsed.scheme not in {"https", "ssh"}:
            raise RepoError("Git repository URL must use HTTPS or SSH.")
        if parsed.query or parsed.fragment or parsed.params:
            raise RepoError("Git repository URL cannot contain query or fragment data.")
        if parsed.password:
            raise RepoError("Git repository URL cannot contain a password.")
        if parsed.scheme == "https" and parsed.username:
            raise RepoError("HTTPS Git URLs cannot contain embedded credentials.")
        if parsed.scheme == "ssh" and parsed.username != "git":
            raise RepoError("SSH Git URLs must use the 'git' user.")
        host = parsed.hostname or ""
    _validate_remote_host(host)
    # Reuse the path-segment and traversal checks used to derive clone paths.
    repo_local_path(normalized)
    return normalized


def _validate_remote_host(host: str) -> None:
    lowered = host.rstrip(".").lower()
    if not lowered or lowered == "localhost" or lowered.endswith(".local"):
        raise RepoError("Local repository hosts are not allowed from the web UI.")
    try:
        address = ipaddress.ip_address(lowered)
    except ValueError:
        if _HOSTNAME_RE.fullmatch(lowered) is None:
            raise RepoError(f"Invalid repository host: {host!r}")
    else:
        if not address.is_global:
            raise RepoError("Private, loopback, and reserved repository IPs are not allowed.")


def list_cloned_repos(repos_dir: str = DEFAULT_REPOS_DIR) -> list[dict[str, str]]:
    """List existing checkouts under the repos dir.

    Returns ``[{"name": <relative path>, "path": <absolute path>}]`` sorted by
    name, e.g. ``github.com/user/repo``.
    """
    base = os.path.realpath(os.path.expanduser(repos_dir))
    repos: list[dict[str, str]] = []
    if not os.path.isdir(base):
        return repos
    for root, dirs, _files in os.walk(base):
        if ".git" in dirs:
            repos.append({"name": os.path.relpath(root, base), "path": root})
            dirs[:] = []  # do not descend into a checkout
    repos.sort(key=lambda r: r["name"])
    return repos


def repo_local_path(url: str, repos_dir: str = DEFAULT_REPOS_DIR) -> str:
    """Map a git URL to its local mirror path under ``repos_dir``.

    ``https://github.com/user/repo.git`` → ``{repos_dir}/github.com/user/repo``
    ``git@github.com:user/repo.git``     → ``{repos_dir}/github.com/user/repo``
    """
    url = url.strip()
    if not url:
        raise RepoError("Empty git repository URL.")

    scp_match = _SCP_LIKE_RE.match(url)
    if scp_match and "://" not in url:
        host = scp_match.group("host")
        path = scp_match.group("path")
    else:
        parsed = urllib.parse.urlparse(url if "://" in url else f"https://{url}")
        host = parsed.hostname or "local"
        path = parsed.path

    path = path.removesuffix(".git").strip("/")
    segments = [s for s in path.split("/") if s]
    if not segments:
        raise RepoError(f"Cannot determine repository name from URL: {url}")
    for segment in [host, *segments]:
        if segment in (".", "..") or not _SAFE_SEGMENT_RE.match(segment):
            raise RepoError(f"Unsafe path segment in repository URL: {segment!r}")
    return os.path.join(os.path.expanduser(repos_dir), host, *segments)


def _clone_env() -> dict[str, str]:
    env = dict(os.environ)
    # Fail fast instead of prompting for credentials on private/missing repos.
    env["GIT_TERMINAL_PROMPT"] = "0"
    return env


async def ensure_repo(url: str, repos_dir: str = DEFAULT_REPOS_DIR) -> str:
    """Clone ``url`` into the repos dir if needed; return the local path."""
    dest = repo_local_path(url, repos_dir)
    if os.path.isdir(os.path.join(dest, ".git")):
        logger.info("Using existing repository checkout: %s", dest)
        return dest
    if os.path.exists(dest):
        raise RepoError(f"Path exists but is not a git repository: {dest}")

    os.makedirs(os.path.dirname(dest), exist_ok=True)
    logger.info("Cloning %s into %s ...", url, dest)
    proc = await asyncio.create_subprocess_exec(
        "git", "clone", "--", url, dest,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
        env=_clone_env(),
    )
    try:
        out, _ = await proc.communicate()
    except asyncio.CancelledError:
        proc.kill()
        raise
    if proc.returncode != 0:
        tail = (out or b"").decode("utf-8", errors="replace")[-500:]
        raise RepoError(f"git clone failed for {url}: {tail}")
    logger.info("Clone complete: %s", dest)
    return dest


def ensure_repo_sync(url: str, repos_dir: str = DEFAULT_REPOS_DIR) -> str:
    """Synchronous variant of :func:`ensure_repo` for the CLI entry point."""
    dest = repo_local_path(url, repos_dir)
    if os.path.isdir(os.path.join(dest, ".git")):
        logger.info("Using existing repository checkout: %s", dest)
        return dest
    if os.path.exists(dest):
        raise RepoError(f"Path exists but is not a git repository: {dest}")

    os.makedirs(os.path.dirname(dest), exist_ok=True)
    logger.info("Cloning %s into %s ...", url, dest)
    result = subprocess.run(
        ["git", "clone", "--", url, dest],
        capture_output=True,
        text=True,
        env=_clone_env(),
    )
    if result.returncode != 0:
        tail = (result.stdout + result.stderr)[-500:]
        raise RepoError(f"git clone failed for {url}: {tail}")
    logger.info("Clone complete: %s", dest)
    return dest


# ── Repository identity ──────────────────────────────────────────────────────


def _git(target: str, *args: str, timeout: int = 15) -> str | None:
    """Run a git command in ``target``; return stdout stripped, or None."""
    try:
        result = subprocess.run(
            ["git", "-C", target, *args],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if result.returncode != 0:
        return None
    return result.stdout.strip()


def capture_repo_identity(target: str) -> dict:
    """Capture the identity of the audit target repository.

    The identity — repo name, HEAD commit, and submodule commits — uniquely
    pins the code that was audited. Branch, origin URL, and a dirty flag are
    captured as extra context. All git calls are best-effort: for a non-git
    target the fields are empty.
    """
    identity: dict = {
        "repo_name": "",
        "repo_url": "",
        "branch": "",
        "commit": "",
        "dirty": False,
        "submodules": [],
    }
    if not os.path.isdir(target):
        return identity
    top = _git(target, "rev-parse", "--show-toplevel")
    if not top:
        return identity

    identity["commit"] = _git(target, "rev-parse", "HEAD") or ""
    identity["branch"] = _git(target, "rev-parse", "--abbrev-ref", "HEAD") or ""
    identity["repo_url"] = _git(target, "remote", "get-url", "origin") or ""
    identity["dirty"] = bool(_git(target, "status", "--porcelain"))

    # Read gitlinks from the superproject tree instead of the submodule
    # worktrees.  ``git submodule status --recursive`` changes its output when
    # a previously uninitialized submodule is cloned, which made the same HEAD
    # produce a different target key depending on local checkout state.
    submodules = []
    for line in (_git(target, "ls-tree", "-r", "HEAD") or "").splitlines():
        metadata, separator, path = line.partition("\t")
        parts = metadata.split()
        if separator and len(parts) == 3 and parts[:2] == ["160000", "commit"]:
            submodules.append({"path": path, "commit": parts[2]})
    identity["submodules"] = submodules

    url = identity["repo_url"]
    if url:
        # Handles both https://host/owner/repo.git and git@host:owner/repo.git.
        identity["repo_name"] = url.removesuffix(".git").rstrip("/").split("/")[-1].split(":")[-1]
    else:
        identity["repo_name"] = os.path.basename(top)
    return identity


def default_audit_output_dir(target: str, results_dir: str = DEFAULT_RESULTS_DIR) -> str:
    """Default output directory for audits of ``target``.

    Layout: ``{results_dir}/{repo}/audit-output-{commit12}`` — the same
    repo+commit always maps to the same directory, so resume works naturally
    and repeated audits of one commit merge into a single output tree.
    Non-git targets fall back to the current date.
    """
    identity = capture_repo_identity(target)
    project = identity["repo_name"] or os.path.basename(os.path.realpath(target))
    stamp = (
        identity["commit"][:12]
        if identity["commit"]
        else datetime.now().strftime("%Y%m%d")
    )
    return os.path.join(
        os.path.expanduser(results_dir), project, f"audit-output-{stamp}"
    )
