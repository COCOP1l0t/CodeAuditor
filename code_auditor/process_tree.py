from __future__ import annotations

import os
import shlex
import time
from contextvars import ContextVar

AUDIT_PROCESS_MARKER_ENV = "CODE_AUDITOR_AUDIT_RUN_ID"
CURRENT_AUDIT_PROCESS_MARKER: ContextVar[str | None] = ContextVar(
    "current_audit_process_marker",
    default=None,
)
PROC_ROOT = "/proc"


def current_audit_subprocess_env(
    base: dict[str, str] | None = None,
) -> dict[str, str]:
    """Copy an environment and attach the current Audit Run marker."""
    environment = dict(os.environ if base is None else base)
    marker = CURRENT_AUDIT_PROCESS_MARKER.get()
    if marker:
        environment[AUDIT_PROCESS_MARKER_ENV] = marker
    return environment


def _process_has_marker(pid: int, marker: str) -> bool:
    expected = f"{AUDIT_PROCESS_MARKER_ENV}={marker}".encode()
    try:
        with open(os.path.join(PROC_ROOT, str(pid), "environ"), "rb") as stream:
            return expected in stream.read().split(b"\0")
    except OSError:
        return False


def _read_process(pid: int) -> dict | None:
    proc_dir = os.path.join(PROC_ROOT, str(pid))
    try:
        with open(os.path.join(proc_dir, "stat"), encoding="utf-8") as stream:
            stat = stream.read()
        closing_paren = stat.rfind(")")
        if closing_paren < 0:
            return None
        fields = stat[closing_paren + 2 :].split()
        state = fields[0]
        ppid = int(fields[1])
        with open(os.path.join(proc_dir, "comm"), encoding="utf-8") as stream:
            name = stream.read().rstrip("\n")
        with open(os.path.join(proc_dir, "cmdline"), "rb") as stream:
            argv = [
                part.decode("utf-8", errors="replace")
                for part in stream.read().split(b"\0")
                if part
            ]
    except (OSError, ValueError, IndexError):
        return None

    return {
        "pid": pid,
        "ppid": ppid,
        "name": name or str(pid),
        "state": state,
        "command": shlex.join(argv) if argv else f"[{name or pid}]",
        "children": [],
    }


def snapshot_process_tree(marker: str) -> dict:
    """Return the live process forest carrying one Audit Run marker."""
    try:
        entries = os.scandir(PROC_ROOT)
    except OSError:
        return {"sampled_at": time.time(), "total": 0, "roots": []}

    nodes: dict[int, dict] = {}
    with entries:
        for entry in entries:
            if not entry.name.isdigit():
                continue
            pid = int(entry.name)
            if not _process_has_marker(pid, marker):
                continue
            process = _read_process(pid)
            if process is not None:
                nodes[pid] = process

    roots: list[dict] = []
    for pid in sorted(nodes):
        node = nodes[pid]
        parent = nodes.get(node["ppid"])
        if parent is None or parent is node:
            roots.append(node)
        else:
            parent["children"].append(node)

    def sort_children(node: dict) -> None:
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
