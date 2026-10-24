"""Offline tests for the CTFTiny adapter and the shared local-CTF helpers."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from code_auditor.bench import Submission, create, registered
from code_auditor.bench.adapters.ctftiny import CTFTinyAdapter
from code_auditor.bench.ctf import (
    CommandResult,
    CTFWorkspaceError,
    LocalCTFWorkspace,
    grade_flag,
    normalize_flag,
    safe_component,
)

FLAG = "flag{unit_test_ground_truth}"


class FakeRunner:
    def __init__(self, *, host_port: str = "0.0.0.0:32768", fail_up: bool = False) -> None:
        self.host_port = host_port
        self.fail_up = fail_up
        self.calls: list[tuple[tuple[str, ...], Path | None]] = []

    def __call__(self, args, cwd):
        argv = tuple(str(part) for part in args)
        self.calls.append((argv, cwd))
        if argv[:3] == ("docker", "network", "create"):
            return CommandResult(argv, cwd, 0, "ctfnet\n", "")
        if "up" in argv:
            if self.fail_up:
                return CommandResult(argv, cwd, 1, "", "boom")
            return CommandResult(argv, cwd, 0, "", "")
        if "config" in argv and "--services" in argv:
            return CommandResult(argv, cwd, 0, "game-server\n", "")
        if "port" in argv:
            return CommandResult(argv, cwd, 0, f"{self.host_port}\n", "")
        if "down" in argv:
            return CommandResult(argv, cwd, 0, "", "")
        return CommandResult(argv, cwd, 0, "", "")


def _make_repo(
    tmp_path: Path,
    *,
    compose: bool = True,
    files: tuple[str, ...] = ("binary",),
    flag: str = FLAG,
    description: str = "Connect with `nc {box} {port}` and get the flag.",
    with_flag: bool = True,
) -> Path:
    repo = tmp_path / "ctftiny"
    challenge = repo / "ctftiny" / "pwn" / "baby"
    challenge.mkdir(parents=True)
    payload = {
        "name": "baby",
        "category": "pwn",
        "description": description,
        "points": 50,
        "files": list(files),
        "compose": compose,
        "internal_port": 8000,
        "box": "pwn.chal.csaw.io",
    }
    if with_flag:
        payload["flag"] = flag
    (challenge / "challenge.json").write_text(json.dumps(payload), encoding="utf-8")
    (challenge / "binary").write_bytes(b"\x7fELF fake binary")
    (challenge / "flag.txt").write_text(flag, encoding="utf-8")
    (challenge / "solve.py").write_text(f"print({flag!r})\n", encoding="utf-8")
    solver = challenge / "test_solver"
    solver.mkdir()
    (solver / "solver.py").write_text(f"# {flag}\n", encoding="utf-8")
    (challenge / "docker-compose.yml").write_text(
        "services:\n  game-server:\n    image: fake\n", encoding="utf-8"
    )
    (repo / "ctftiny.json").write_text(
        json.dumps(
            {
                "pwn-baby": {
                    "year": "2019",
                    "event": "CSAW-Quals",
                    "category": "pwn",
                    "challenge": "baby",
                    "path": "ctftiny/pwn/baby",
                }
            }
        ),
        encoding="utf-8",
    )
    return repo


def _adapter(repo: Path, *, runner: FakeRunner | None = None, work_root: Path | None = None) -> CTFTinyAdapter:
    return CTFTinyAdapter(
        repo_dir=repo,
        work_root=work_root or repo.parent / "work",
        runner=runner or FakeRunner(),
    )


def test_lists_instances_without_exposing_the_flag(tmp_path: Path) -> None:
    adapter = _adapter(_make_repo(tmp_path))

    instances = adapter.list_instances()

    assert [instance.instance_id for instance in instances] == ["pwn-baby"]
    metadata = instances[0].metadata
    assert metadata["category"] == "pwn"
    assert metadata["compose"] is True
    assert metadata["points"] == 50.0
    assert "flag" not in metadata
    assert FLAG not in json.dumps(metadata)


def test_open_task_copies_only_the_allowlist_and_substitutes_the_target(tmp_path: Path) -> None:
    runner = FakeRunner()
    adapter = _adapter(_make_repo(tmp_path), runner=runner)
    instance = adapter.list_instances()[0]

    task = adapter.open_task(instance)

    workdir = Path(task.metadata["workdir"])
    assert (workdir / "binary").is_file()
    assert not (workdir / "flag.txt").exists()
    assert not (workdir / "test_solver").exists()
    assert not (workdir / "solve.py").exists()
    assert task.target == "127.0.0.1:32768"
    assert task.scenario == "container"
    assert "127.0.0.1:32768" in task.prompt
    assert "nc {box} {port}" not in task.prompt
    assert FLAG not in task.prompt
    docker = " ".join(" ".join(argv) for argv, _cwd in runner.calls)
    assert "docker network create ctfnet" in docker
    assert "compose -p" in docker and "up -d" in docker

    adapter.close(instance)
    assert not workdir.exists()
    assert any("down" in argv for argv, _cwd in runner.calls)
    calls = len(runner.calls)
    adapter.close(instance)  # idempotent
    assert len(runner.calls) == calls


def test_offline_task_does_not_touch_docker(tmp_path: Path) -> None:
    runner = FakeRunner()
    repo = _make_repo(tmp_path, compose=False, files=("binary",))
    adapter = _adapter(repo, runner=runner)

    task = adapter.open_task(adapter.list_instances()[0])

    assert runner.calls == []
    assert task.scenario == "workspace"
    assert task.target == task.metadata["workdir"]
    assert "No network service" in task.prompt
    adapter.close(task.instance)


def test_grade_is_an_exact_trimmed_comparison(tmp_path: Path) -> None:
    adapter = _adapter(_make_repo(tmp_path))
    instance = adapter.list_instances()[0]

    correct = adapter.grade(
        instance, Submission(instance_id="pwn-baby", kind="flag", value=f"  {FLAG}\n")
    )
    assert correct.success is True
    assert correct.score == 50.0
    assert correct.detail["matched"] is True

    wrong = adapter.grade(
        instance, Submission(instance_id="pwn-baby", kind="flag", value="flag{nope}")
    )
    assert wrong.success is False
    assert wrong.score == 0.0

    empty = adapter.grade(
        instance, Submission(instance_id="pwn-baby", kind="flag", value="  ")
    )
    assert empty.success is False
    assert empty.detail["error"] == "empty flag"

    with pytest.raises(ValueError, match="only accept kind='flag'"):
        adapter.grade(
            instance, Submission(instance_id="pwn-baby", kind="patch", value=FLAG)
        )
    with pytest.raises(ValueError, match="does not match"):
        adapter.grade(
            instance, Submission(instance_id="other", kind="flag", value=FLAG)
        )


def test_escaping_or_absolute_handouts_are_rejected(tmp_path: Path) -> None:
    repo = _make_repo(tmp_path, compose=False)
    challenge = repo / "ctftiny" / "pwn" / "baby"
    payload = json.loads((challenge / "challenge.json").read_text(encoding="utf-8"))
    payload["files"] = ["../../outside.txt"]
    (challenge / "challenge.json").write_text(json.dumps(payload), encoding="utf-8")
    adapter = _adapter(repo)

    with pytest.raises(CTFWorkspaceError, match="escaping handout"):
        adapter.open_task(adapter.list_instances()[0])
    assert not list((repo.parent / "work").iterdir())


def test_symlinked_handout_outside_the_challenge_is_rejected(tmp_path: Path) -> None:
    repo = _make_repo(tmp_path, compose=False)
    challenge = repo / "ctftiny" / "pwn" / "baby"
    outside = tmp_path / "outside.txt"
    outside.write_text("secret", encoding="utf-8")
    (challenge / "link").symlink_to(outside)
    payload = json.loads((challenge / "challenge.json").read_text(encoding="utf-8"))
    payload["files"] = ["link"]
    (challenge / "challenge.json").write_text(json.dumps(payload), encoding="utf-8")

    adapter = _adapter(repo)
    with pytest.raises(CTFWorkspaceError, match="outside the challenge"):
        adapter.open_task(adapter.list_instances()[0])


def test_ground_truth_in_an_allowlisted_file_is_rejected(tmp_path: Path) -> None:
    repo = _make_repo(tmp_path, compose=False, files=("leak.txt",))
    (repo / "ctftiny" / "pwn" / "baby" / "leak.txt").write_text(
        f"prefix {FLAG} suffix", encoding="utf-8"
    )
    adapter = _adapter(repo)

    with pytest.raises(CTFWorkspaceError, match="Ground-truth flag"):
        adapter.open_task(adapter.list_instances()[0])


def test_preflight_loads_every_challenge(tmp_path: Path) -> None:
    adapter = _adapter(_make_repo(tmp_path))
    adapter.preflight()  # must not raise for a valid checkout


def test_flag_in_the_prompt_is_rejected(tmp_path: Path) -> None:
    repo = _make_repo(tmp_path, compose=False, description=f"Hint: {FLAG}")
    adapter = _adapter(repo)

    with pytest.raises(CTFWorkspaceError, match="leak its flag"):
        adapter.open_task(adapter.list_instances()[0])


def test_compose_failure_stops_the_stack_and_removes_the_workspace(tmp_path: Path) -> None:
    runner = FakeRunner(fail_up=True)
    adapter = _adapter(_make_repo(tmp_path), runner=runner)
    instance = adapter.list_instances()[0]

    with pytest.raises(CTFWorkspaceError, match="compose up failed"):
        adapter.open_task(instance)

    assert any("down" in argv for argv, _cwd in runner.calls)
    assert not list((tmp_path / "work").glob("*"))


def test_missing_flag_and_bad_manifest_fail_loudly(tmp_path: Path) -> None:
    repo = _make_repo(tmp_path, with_flag=False)
    with pytest.raises(CTFWorkspaceError, match="has no flag"):
        _adapter(repo).list_instances()

    empty = tmp_path / "empty"
    empty.mkdir()
    with pytest.raises(CTFWorkspaceError, match="manifest is unreadable"):
        CTFTinyAdapter(repo_dir=empty)


def test_registry_creates_ctftiny(tmp_path: Path) -> None:
    assert "ctftiny" in registered()
    adapter = create("ctftiny", repo_dir=_make_repo(tmp_path))
    assert isinstance(adapter, CTFTinyAdapter)
    assert adapter.list_instances()[0].instance_id == "pwn-baby"


def test_shared_helpers(tmp_path: Path) -> None:
    assert normalize_flag("  flag{x}\n") == "flag{x}"
    assert safe_component("Pwn/Baby Boi") == "pwn_baby_boi"
    outcome = grade_flag(
        "x", Submission(instance_id="x", kind="flag", value="flag{x}"), "flag{x}", score=7
    )
    assert outcome.success is True and outcome.score == 7

    challenge_dir = tmp_path / "challenge"
    challenge_dir.mkdir()
    workspace = LocalCTFWorkspace(tmp_path / "missing-work", challenge_dir, ())
    workspace.cleanup()  # absent workspace is a no-op
