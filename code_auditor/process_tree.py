from __future__ import annotations

import os
import shlex
import subprocess
import time
from contextvars import ContextVar
from typing import Any

import psutil

AUDIT_PROCESS_MARKER_ENV = "CODE_AUDITOR_AUDIT_RUN_ID"
CURRENT_AUDIT_PROCESS_MARKER: ContextVar[str | None] = ContextVar(
    "current_audit_process_marker",
    default=None,
)

_PROCESS_ACCESS_ERRORS = (psutil.Error, OSError)


def current_audit_subprocess_env(
    base: dict[str, str] | None = None,
) -> dict[str, str]:
    """Copy an environment and attach the current Audit Run marker."""
    environment = dict(os.environ if base is None else base)
    marker = CURRENT_AUDIT_PROCESS_MARKER.get()
    if marker:
        environment[AUDIT_PROCESS_MARKER_ENV] = marker
    return environment


def _environment_has_marker(
    environment: dict[str, str], marker: str, env_var: str
) -> bool:
    wanted = f"{env_var}={marker}"
    return any(
        f"{key}={value}" == wanted
        for key, value in environment.items()
    )


def _process_has_marker(
    process: psutil.Process, marker: str, env_var: str
) -> bool:
    try:
        return _environment_has_marker(process.environ(), marker, env_var)
    except _PROCESS_ACCESS_ERRORS:
        return False


def process_has_marker(
    pid: int,
    marker: str,
    env_var: str = AUDIT_PROCESS_MARKER_ENV,
) -> bool:
    """Return whether a live process has the exact marker in its environment."""
    if pid == os.getpid():
        return False
    try:
        process = psutil.Process(pid)
    except _PROCESS_ACCESS_ERRORS:
        return False
    return _process_has_marker(process, marker, env_var)


def marked_process_ids(
    marker: str,
    env_var: str = AUDIT_PROCESS_MARKER_ENV,
) -> list[int]:
    """Return same-user processes carrying an exact environment marker."""
    pids: list[int] = []
    for process in psutil.process_iter():
        try:
            pid = int(process.pid)
        except _PROCESS_ACCESS_ERRORS:
            continue
        if pid == os.getpid():
            continue
        if _process_has_marker(process, marker, env_var):
            pids.append(pid)
    return sorted(pids)


def _status_character(status: str) -> str:
    return {
        psutil.STATUS_RUNNING: "R",
        psutil.STATUS_SLEEPING: "S",
        psutil.STATUS_DISK_SLEEP: "D",
        psutil.STATUS_STOPPED: "T",
        psutil.STATUS_ZOMBIE: "Z",
    }.get(status, (status[:1] or "?").upper())


def _format_command(argv: list[str], name: str, pid: int) -> str:
    if not argv:
        return f"[{name or pid}]"
    if os.name == "nt":
        return subprocess.list2cmdline(argv)
    return shlex.join(argv)


def _read_process(process: psutil.Process) -> dict[str, Any] | None:
    try:
        pid = int(process.pid)
        ppid = int(process.ppid())
        name = process.name()
        argv = list(process.cmdline())
        status = process.status()
    except _PROCESS_ACCESS_ERRORS:
        return None

    return {
        "pid": pid,
        "ppid": ppid,
        "name": name or str(pid),
        "state": _status_character(status),
        "command": _format_command(argv, name, pid),
        "children": [],
    }


def snapshot_process_tree(marker: str) -> dict[str, Any]:
    """Return the live process forest carrying one Audit Run marker.

    ``psutil`` provides a common implementation across Linux, macOS, and
    Windows. Access-denied and short-lived processes are skipped rather than
    failing the whole Web status request.
    """
    nodes: dict[int, dict[str, Any]] = {}
    for process in psutil.process_iter():
        try:
            pid = int(process.pid)
        except _PROCESS_ACCESS_ERRORS:
            continue
        if pid == os.getpid() or not _process_has_marker(
            process, marker, AUDIT_PROCESS_MARKER_ENV
        ):
            continue
        node = _read_process(process)
        if node is not None:
            nodes[pid] = node

    roots: list[dict[str, Any]] = []
    for pid in sorted(nodes):
        node = nodes[pid]
        parent = nodes.get(node["ppid"])
        if parent is None or parent is node:
            roots.append(node)
        else:
            parent["children"].append(node)

    def sort_children(node: dict[str, Any]) -> None:
        node["children"].sort(key=lambda child: child["pid"])
        for child in node["children"]:
            sort_children(child)

    for root in roots:
        sort_children(root)

    return {
        "sampled_at": time.time(),
        "total": len(nodes),
        "roots": roots,
    }
