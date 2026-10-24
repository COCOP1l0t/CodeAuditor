"""Offline tests for the CyBench adapter."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from code_auditor.bench import Submission, create, registered
from code_auditor.bench.adapters.cybench import CyBenchAdapter
from code_auditor.bench.ctf import CommandResult, CTFWorkspaceError, run_command

OFFLINE = "benchmark/demo/crypto/easy-task"
SERVER = "benchmark/demo/web/[Hard] server task"
FLAG = "flag{cybench_unit_test}"


class FixtureRunner:
    """Run fixture shell scripts for real; intercept only Docker commands."""

    def __init__(self) -> None:
        self.calls: list[tuple[tuple[str, ...], Path | None]] = []

    def __call__(self, args, cwd):
        argv = tuple(str(part) for part in args)
        self.calls.append((argv, cwd))
        if argv and argv[0] == "bash":
            return run_command(argv, cwd)
        if argv[:3] == ("docker", "network", "create"):
            return CommandResult(argv, cwd, 0, "", "")
        return CommandResult(argv, cwd, 0, "", "")


def _write_task(
    repo: Path,
    relative: str,
    *,
    target_host: str = "",
    requirements: bool = False,
    copy_flag: bool = False,
    init_exit: int = 0,
    start: bool = False,
) -> Path:
    task = repo / relative
    (task / "challenge").mkdir(parents=True)
    (task / "metadata").mkdir()
    (task / "challenge" / "handout.txt").write_text("handout\n", encoding="utf-8")
    (task / "challenge" / "flag.txt").write_text(FLAG, encoding="utf-8")
    (task / "metadata" / "metadata.json").write_text(
        json.dumps(
            {
                "categories": ["crypto", "web"],
                "difficulty": "2",
                "easy_prompt": "Easy description.",
                "hard_prompt": "Recover the flag from the provided handout.",
                "target_host": target_host,
                "subtasks": [
                    {"question": "Which file is a handout?", "answer": "handout.txt"},
                    {
                        "question": "What is the flag?",
                        "answer": FLAG,
                        "answer_format": "flag{***}",
                        "hints": ["do not leak this hint"],
                    },
                ],
            }
        ),
        encoding="utf-8",
    )
    copy_lines = ['cp challenge/handout.txt "$TMP_DIR"']
    if copy_flag:
        copy_lines.append('cp challenge/flag.txt "$TMP_DIR"')
    (task / "init_script.sh").write_text(
        "#!/bin/bash\nTMP_DIR=\"$1\"\n"
        + "\n".join(copy_lines)
        + f"\nexit {init_exit}\n",
        encoding="utf-8",
    )
    if requirements:
        (task / "metadata" / "requirements.sh").write_text(
            "#!/bin/bash\ntouch requirements.marker\n", encoding="utf-8"
        )
    if start:
        (task / "start_docker.sh").write_text(
            "#!/bin/bash\ntouch started.marker\n", encoding="utf-8"
        )
        (task / "stop_docker.sh").write_text(
            "#!/bin/bash\ntouch stopped.marker\n", encoding="utf-8"
        )
    return task


def _make_repo(
    tmp_path: Path,
    *,
    include_malicious: bool = False,
    server_target: str = "otp:80",
) -> Path:
    repo = tmp_path / "cybench"
    repo.mkdir()
    _write_task(repo, OFFLINE, requirements=True)
    _write_task(repo, SERVER, target_host=server_target, start=True)
    paths = [OFFLINE, SERVER]
    if include_malicious:
        malicious = "benchmark/demo/rev/leaky"
        _write_task(repo, malicious, copy_flag=True)
        paths.append(malicious)
    (repo / "task_list.txt").write_text("\n".join(paths) + "\n", encoding="utf-8")
    return repo


def _adapter(
    repo: Path,
    *,
    runner: FixtureRunner | None = None,
    start_services: bool = True,
    run_requirements: bool = False,
) -> CyBenchAdapter:
    return CyBenchAdapter(
        repo_dir=repo,
        work_root=repo.parent / "work",
        runner=runner or FixtureRunner(),
        start_services=start_services,
        run_requirements=run_requirements,
    )


def _instance(adapter: CyBenchAdapter, task_path: str):
    return next(item for item in adapter.list_instances() if item.instance_id == task_path)


def test_lists_unguided_tasks_without_answers(tmp_path: Path) -> None:
    adapter = _adapter(_make_repo(tmp_path))

    instances = adapter.list_instances()

    assert [item.instance_id for item in instances] == [OFFLINE, SERVER]
    offline, server = instances
    assert offline.metadata["categories"] == ["crypto", "web"]
    assert offline.metadata["subtask_count"] == 2
    assert offline.metadata["target_host"] == ""
    assert server.metadata["target_host"] == "otp:80"
    assert server.metadata["requires_shared_network"] is True
    assert FLAG not in json.dumps([item.metadata for item in instances])


def test_offline_task_materializes_handouts_and_cleans_up(tmp_path: Path) -> None:
    runner = FixtureRunner()
    adapter = _adapter(_make_repo(tmp_path), runner=runner)

    task = adapter.open_task(_instance(adapter, OFFLINE))

    workdir = Path(task.metadata["workdir"])
    assert (workdir / "handout.txt").read_text(encoding="utf-8") == "handout\n"
    assert not (workdir / "flag.txt").exists()
    assert task.scenario == "workspace"
    assert task.target == str(workdir)
    assert "Recover the flag" in task.prompt
    assert "What is the flag?" in task.prompt
    assert "flag{***}" in task.prompt
    assert "do not leak this hint" not in task.prompt
    assert FLAG not in task.prompt
    assert runner.calls and runner.calls[0][0][0] == "bash"

    adapter.close(task.instance)
    assert not workdir.exists()
    adapter.close(task.instance)  # idempotent


def test_server_task_starts_and_stops_its_official_scripts(tmp_path: Path) -> None:
    runner = FixtureRunner()
    adapter = _adapter(_make_repo(tmp_path), runner=runner)
    task_dir = tmp_path / "cybench" / SERVER

    task = adapter.open_task(_instance(adapter, SERVER))

    assert task.target == "otp:80"
    assert task.scenario == "container"
    assert task.metadata["services_started"] is True
    assert (task_dir / "started.marker").is_file()
    assert any(argv[:3] == ("docker", "network", "create") for argv, _cwd in runner.calls)

    adapter.close(task.instance)
    assert (task_dir / "stopped.marker").is_file()


def test_start_services_false_does_not_run_docker_scripts(tmp_path: Path) -> None:
    runner = FixtureRunner()
    adapter = _adapter(
        _make_repo(tmp_path), runner=runner, start_services=False
    )

    task = adapter.open_task(_instance(adapter, SERVER))

    task_dir = tmp_path / "cybench" / SERVER
    assert not (task_dir / "started.marker").exists()
    assert task.metadata["services_started"] is False
    assert "did not start the task service" in task.prompt
    assert not any(argv[:3] == ("docker", "network", "create") for argv, _cwd in runner.calls)
    adapter.close(task.instance)


def test_requirements_are_opt_in(tmp_path: Path) -> None:
    repo = _make_repo(tmp_path)
    task_dir = repo / OFFLINE
    default_adapter = _adapter(repo)
    default_task = default_adapter.open_task(_instance(default_adapter, OFFLINE))
    assert not (task_dir / "requirements.marker").exists()
    default_adapter.close(default_task.instance)

    adapter = _adapter(repo, run_requirements=True)
    task = adapter.open_task(_instance(adapter, OFFLINE))
    assert (task_dir / "requirements.marker").is_file()
    adapter.close(task.instance)


def test_init_script_copying_the_flag_is_rejected(tmp_path: Path) -> None:
    repo = _make_repo(tmp_path, include_malicious=True)
    adapter = _adapter(repo)

    with pytest.raises(CTFWorkspaceError, match="Ground-truth flag"):
        adapter.open_task(_instance(adapter, "benchmark/demo/rev/leaky"))

    assert not list((repo.parent / "work").glob("*"))


def test_failing_init_script_cleans_up(tmp_path: Path) -> None:
    repo = tmp_path / "cybench"
    repo.mkdir()
    _write_task(repo, OFFLINE, init_exit=7)
    (repo / "task_list.txt").write_text(OFFLINE + "\n", encoding="utf-8")
    adapter = _adapter(repo)

    with pytest.raises(CTFWorkspaceError, match="init_script.sh failed"):
        adapter.open_task(_instance(adapter, OFFLINE))

    assert not list((repo.parent / "work").glob("*"))


def test_grading_is_exact_and_ignores_answer_format(tmp_path: Path) -> None:
    adapter = _adapter(_make_repo(tmp_path))
    instance = _instance(adapter, OFFLINE)

    assert adapter.grade(
        instance, Submission(instance_id=OFFLINE, kind="flag", value=f"  {FLAG} ")
    ).success is True
    assert adapter.grade(
        instance, Submission(instance_id=OFFLINE, kind="flag", value="flag{wrong}")
    ).success is False
    assert adapter.grade(
        instance, Submission(instance_id=OFFLINE, kind="flag", value="   ")
    ).detail["error"] == "empty flag"

    with pytest.raises(ValueError, match="only accept kind='flag'"):
        adapter.grade(instance, Submission(instance_id=OFFLINE, kind="patch", value=FLAG))
    with pytest.raises(ValueError, match="does not match"):
        adapter.grade(instance, Submission(instance_id=SERVER, kind="flag", value=FLAG))


def test_unknown_task_and_empty_checkout_fail(tmp_path: Path) -> None:
    adapter = _adapter(_make_repo(tmp_path))
    with pytest.raises(CTFWorkspaceError, match="Unknown CyBench task"):
        adapter.grade(
            "benchmark/nope",
            Submission(instance_id="benchmark/nope", kind="flag", value=FLAG),
        )

    empty = tmp_path / "empty"
    empty.mkdir()
    with pytest.raises(CTFWorkspaceError, match="No CyBench task list"):
        CyBenchAdapter(repo_dir=empty)


def test_preflight_loads_every_task(tmp_path: Path) -> None:
    _adapter(_make_repo(tmp_path)).preflight()


def test_fallback_discovers_tasks_without_a_task_list(tmp_path: Path) -> None:
    repo = tmp_path / "cybench"
    repo.mkdir()
    _write_task(repo, OFFLINE)
    adapter = _adapter(repo)

    assert [item.instance_id for item in adapter.list_instances()] == [OFFLINE]


def test_registry_creates_cybench(tmp_path: Path) -> None:
    assert "cybench" in registered()
    adapter = create("cybench", repo_dir=_make_repo(tmp_path))
    assert isinstance(adapter, CyBenchAdapter)
    assert len(adapter.list_instances()) == 2
