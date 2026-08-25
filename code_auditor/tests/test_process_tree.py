from __future__ import annotations

import shlex
import subprocess
import sys
import time
from pathlib import Path

import pytest

from code_auditor import agent
from code_auditor import process_tree


def _write_process(
    proc_root: Path,
    *,
    pid: int,
    ppid: int,
    marker: str | None,
    name: str,
    argv: list[str],
) -> None:
    proc_dir = proc_root / str(pid)
    proc_dir.mkdir()
    environment = [b"BASE=value"]
    if marker is not None:
        environment.append(
            f"{process_tree.AUDIT_PROCESS_MARKER_ENV}={marker}".encode()
        )
    (proc_dir / "environ").write_bytes(b"\0".join(environment) + b"\0")
    (proc_dir / "stat").write_text(
        f"{pid} ({name}) S {ppid} 0 0 0\n",
        encoding="utf-8",
    )
    (proc_dir / "comm").write_text(f"{name}\n", encoding="utf-8")
    (proc_dir / "cmdline").write_bytes(
        b"\0".join(argument.encode() for argument in argv) + b"\0"
    )


def test_snapshot_process_tree_builds_marked_parent_child_relationships(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    proc_root = tmp_path / "proc"
    proc_root.mkdir()
    marker = "audit-marker"
    _write_process(
        proc_root,
        pid=101,
        ppid=1,
        marker=marker,
        name="agent host",
        argv=["python", "-m", "agent_host"],
    )
    _write_process(
        proc_root,
        pid=102,
        ppid=101,
        marker=marker,
        name="bash",
        argv=["bash", "-lc", "printf 'hello world'"],
    )
    _write_process(
        proc_root,
        pid=103,
        ppid=102,
        marker=marker,
        name="worker",
        argv=["worker", "--mode", "audit"],
    )
    _write_process(
        proc_root,
        pid=999,
        ppid=1,
        marker="another-audit",
        name="unrelated",
        argv=["unrelated"],
    )
    monkeypatch.setattr(process_tree, "PROC_ROOT", str(proc_root))

    snapshot = process_tree.snapshot_process_tree(marker)

    assert snapshot["total"] == 3
    assert len(snapshot["roots"]) == 1
    root = snapshot["roots"][0]
    assert (root["pid"], root["ppid"], root["name"]) == (101, 1, "agent host")
    child = root["children"][0]
    assert (child["pid"], child["ppid"]) == (102, 101)
    assert child["command"] == shlex.join(
        ["bash", "-lc", "printf 'hello world'"]
    )
    assert child["children"][0]["pid"] == 103


def test_agent_subprocess_env_inherits_current_audit_marker() -> None:
    token = process_tree.CURRENT_AUDIT_PROCESS_MARKER.set("run-marker")
    try:
        environment = agent._AgentRunControl().subprocess_env()
    finally:
        process_tree.CURRENT_AUDIT_PROCESS_MARKER.reset(token)

    assert environment[process_tree.AUDIT_PROCESS_MARKER_ENV] == "run-marker"
    assert environment[agent.AGENT_PROCESS_MARKER_ENV]


def test_current_audit_subprocess_env_marks_non_agent_commands() -> None:
    token = process_tree.CURRENT_AUDIT_PROCESS_MARKER.set("git-run-marker")
    try:
        environment = process_tree.current_audit_subprocess_env({"BASE": "value"})
    finally:
        process_tree.CURRENT_AUDIT_PROCESS_MARKER.reset(token)

    assert environment == {
        "BASE": "value",
        process_tree.AUDIT_PROCESS_MARKER_ENV: "git-run-marker",
    }


@pytest.mark.skipif(not Path("/proc").is_dir(), reason="requires Linux procfs")
def test_snapshot_process_tree_reads_a_live_marked_process() -> None:
    marker = "live-process-marker"
    token = process_tree.CURRENT_AUDIT_PROCESS_MARKER.set(marker)
    try:
        environment = process_tree.current_audit_subprocess_env()
    finally:
        process_tree.CURRENT_AUDIT_PROCESS_MARKER.reset(token)
    child = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(30)"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env=environment,
    )
    try:
        deadline = time.monotonic() + 2
        snapshot = process_tree.snapshot_process_tree(marker)
        while snapshot["total"] != 1 and time.monotonic() < deadline:
            time.sleep(0.02)
            snapshot = process_tree.snapshot_process_tree(marker)

        assert snapshot["total"] == 1
        assert snapshot["roots"][0]["pid"] == child.pid
        assert "time.sleep(30)" in snapshot["roots"][0]["command"]
    finally:
        child.terminate()
        try:
            child.wait(timeout=1)
        except subprocess.TimeoutExpired:
            child.kill()
            child.wait(timeout=1)
