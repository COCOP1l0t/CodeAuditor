from __future__ import annotations

import os
import shlex
import subprocess
import sys
import time

import pytest

from code_auditor import agent
from code_auditor import process_tree


class FakeProcess:
    def __init__(
        self,
        *,
        pid: int,
        ppid: int,
        environment: dict[str, str],
        name: str,
        argv: list[str],
        status: str = "sleeping",
    ) -> None:
        self.pid = pid
        self._ppid = ppid
        self._environment = environment
        self._name = name
        self._argv = argv
        self._status = status

    def environ(self) -> dict[str, str]:
        return dict(self._environment)

    def ppid(self) -> int:
        return self._ppid

    def name(self) -> str:
        return self._name

    def cmdline(self) -> list[str]:
        return list(self._argv)

    def status(self) -> str:
        return self._status


def _process(
    *,
    pid: int,
    ppid: int,
    marker: str | None,
    name: str,
    argv: list[str],
    status: str = "sleeping",
) -> FakeProcess:
    environment = {"BASE": "value"}
    if marker is not None:
        environment[process_tree.AUDIT_PROCESS_MARKER_ENV] = marker
    return FakeProcess(
        pid=pid,
        ppid=ppid,
        environment=environment,
        name=name,
        argv=argv,
        status=status,
    )


def test_snapshot_process_tree_builds_marked_parent_child_relationships(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    marker = "audit-marker"
    processes = [
        _process(
            pid=101,
            ppid=1,
            marker=marker,
            name="agent host",
            argv=["python", "-m", "agent_host"],
            status="running",
        ),
        _process(
            pid=102,
            ppid=101,
            marker=marker,
            name="bash",
            argv=["bash", "-lc", "printf 'hello world'"],
        ),
        _process(
            pid=103,
            ppid=102,
            marker=marker,
            name="worker",
            argv=["worker", "--mode", "audit"],
        ),
        _process(
            pid=999,
            ppid=1,
            marker="another-audit",
            name="unrelated",
            argv=["unrelated"],
        ),
    ]
    monkeypatch.setattr(process_tree.psutil, "process_iter", lambda: iter(processes))

    snapshot = process_tree.snapshot_process_tree(marker)

    assert snapshot["total"] == 3
    assert len(snapshot["roots"]) == 1
    root = snapshot["roots"][0]
    assert (root["pid"], root["ppid"], root["name"], root["state"]) == (
        101,
        1,
        "agent host",
        "R",
    )
    child = root["children"][0]
    assert (child["pid"], child["ppid"]) == (102, 101)
    expected_command = (
        subprocess.list2cmdline(["bash", "-lc", "printf 'hello world'"])
        if os.name == "nt"
        else shlex.join(["bash", "-lc", "printf 'hello world'"])
    )
    assert child["command"] == expected_command
    assert child["children"][0]["pid"] == 103


def test_snapshot_skips_processes_that_deny_environment_access(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class DeniedProcess(FakeProcess):
        def environ(self) -> dict[str, str]:
            raise process_tree.psutil.AccessDenied(self.pid)

    denied = DeniedProcess(
        pid=201,
        ppid=1,
        environment={},
        name="protected",
        argv=["protected"],
    )
    monkeypatch.setattr(process_tree.psutil, "process_iter", lambda: iter([denied]))

    snapshot = process_tree.snapshot_process_tree("marker")
    assert isinstance(snapshot["sampled_at"], float)
    assert snapshot["total"] == 0
    assert snapshot["roots"] == []


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


def test_snapshot_process_tree_reads_a_live_marked_process() -> None:
    marker = "live-process-marker"
    environment = process_tree.current_audit_subprocess_env()
    environment[process_tree.AUDIT_PROCESS_MARKER_ENV] = marker
    child = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(30)"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env=environment,
    )
    try:
        deadline = time.monotonic() + 5
        snapshot = process_tree.snapshot_process_tree(marker)
        while snapshot["total"] != 1 and time.monotonic() < deadline:
            time.sleep(0.05)
            snapshot = process_tree.snapshot_process_tree(marker)

        assert snapshot["total"] == 1
        assert snapshot["roots"][0]["pid"] == child.pid
        assert "time.sleep(30)" in snapshot["roots"][0]["command"]
    finally:
        child.terminate()
        try:
            child.wait(timeout=2)
        except subprocess.TimeoutExpired:
            child.kill()
            child.wait(timeout=2)
