"""Offline tests for the sequential benchmark runner."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from code_auditor.bench import (
    BenchRunner,
    BenchRunError,
    InstanceSpec,
    Outcome,
    Submission,
    extract_flag,
)
from code_auditor.bench.base import BenchTask
from code_auditor.config import AuditConfig

EXPECTED = "flag{runner_expected}"


class FakeAdapter:
    name = "fake"

    def __init__(self, root: Path, *, fail_open=(), fail_close=(), grade_error=()) -> None:
        self.root = root
        self.instances = [
            InstanceSpec("fake", "one", {"target": "t1"}),
            InstanceSpec("fake", "two", {"target": "t2"}),
        ]
        self.fail_open = set(fail_open)
        self.fail_close = set(fail_close)
        self.grade_error = set(grade_error)
        self.opened: list[str] = []
        self.closed: list[str] = []
        self.graded: list[Submission] = []
        self.preflighted = 0

    def preflight(self) -> None:
        self.preflighted += 1

    def list_instances(self, **_kwargs):
        return list(self.instances)

    def open_task(self, instance):
        if instance.instance_id in self.fail_open:
            raise RuntimeError("open failed")
        self.opened.append(instance.instance_id)
        workdir = self.root / f"work-{instance.instance_id}"
        workdir.mkdir(parents=True, exist_ok=True)
        return BenchTask(
            instance=instance,
            prompt="Solve the fake task.",
            target=str(workdir),
            scenario="workspace",
            metadata={"workdir": str(workdir)},
        )

    def grade(self, instance, submission: Submission) -> Outcome:
        if instance.instance_id in self.grade_error:
            raise RuntimeError("grade failed")
        self.graded.append(submission)
        matched = submission.value == EXPECTED
        return Outcome(
            instance_id=instance.instance_id,
            success=matched,
            score=1.0 if matched else 0.0,
            detail={"matched": matched, "task": "fake"},
        )

    def close(self, instance) -> None:
        self.closed.append(instance.instance_id)
        if instance.instance_id in self.fail_close:
            raise RuntimeError("cleanup failed")

    def expected_flag(self, instance) -> str:
        return EXPECTED


class FakeAgent:
    def __init__(self, replies: list[str], *, leak: str = EXPECTED) -> None:
        self.replies = list(replies)
        self.leak = leak
        self.calls: list[dict] = []

    async def __call__(
        self,
        prompt,
        config,
        *,
        cwd,
        max_turns,
        log_file,
        trajectory,
    ):
        self.calls.append(
            {
                "prompt": prompt,
                "config": config,
                "cwd": cwd,
                "max_turns": max_turns,
                "log_file": log_file,
                "trajectory": trajectory,
            }
        )
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        reply = self.replies.pop(0)
        log_path.write_text(f"tool output: {self.leak}\n{reply}\n", encoding="utf-8")
        if trajectory:
            trajectory_path = (
                log_path.parent.parent / "trajectories" / log_path.parent.name / "agent.json"
            )
            trajectory_path.parent.mkdir(parents=True, exist_ok=True)
            trajectory_path.write_text(
                json.dumps({"message": f"observed {self.leak}"}), encoding="utf-8"
            )
        return reply


def _config(tmp_path: Path) -> AuditConfig:
    return AuditConfig(
        target=str(tmp_path / "target"),
        output_dir=str(tmp_path / "out"),
        agent_timeout_seconds=None,
    )


def _runner(tmp_path: Path, adapter: FakeAdapter, agent: FakeAgent, **options) -> BenchRunner:
    return BenchRunner(
        adapter,
        _config(tmp_path),
        output_dir=tmp_path / "run",
        agent_runner=agent,
        **options,
    )


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("ANSWER: flag{ok}", "flag{ok}"),
        ("FLAG: flag{a!b}", "flag{a!b}"),
        ("prefix\npicoCTF{some_flag}\n", "picoCTF{some_flag}"),
        ("ANSWER: `flag{quoted}`", "flag{quoted}"),
        ("ANSWER: secret phrase", "secret phrase"),
        ("ANSWER: flag{x} and some explanation", "flag{x}"),
        ("nothing useful here", None),
        ("done", None),
        ("", None),
        (None, None),
    ],
)
def test_extract_flag_variants(text, expected) -> None:
    assert extract_flag(text) == expected


def test_runner_success_writes_summary_and_scrubs(tmp_path: Path) -> None:
    adapter = FakeAdapter(tmp_path)
    agent = FakeAgent(["analysis\nANSWER: flag{runner_expected}"])
    runner = _runner(tmp_path, adapter, agent)

    run = asyncio_run(runner.run(instances=[adapter.instances[0]]))

    assert run.summary()["succeeded"] == 1
    assert run.results[0].status == "succeeded"
    assert run.results[0].score == 1.0
    assert run.results[0].success is True
    assert adapter.closed == ["one"]
    assert adapter.preflighted == 1
    assert "ANSWER:" in agent.calls[0]["prompt"]
    assert agent.calls[0]["trajectory"] is False
    assert agent.calls[0]["config"].trajectory_enabled is False
    assert agent.calls[0]["config"].output_dir == str(tmp_path / "run")

    log = tmp_path / "run" / "one" / "agent.log"
    assert "[REDACTED]" in log.read_text(encoding="utf-8")
    assert EXPECTED not in log.read_text(encoding="utf-8")
    results = (tmp_path / "run" / "bench-results.json").read_text(encoding="utf-8")
    assert EXPECTED not in results
    assert json.loads(results)["succeeded"] == 1
    assert (tmp_path / "run" / "bench-results.jsonl").is_file()


def test_wrong_flag_is_failed_and_scrubbed(tmp_path: Path) -> None:
    adapter = FakeAdapter(tmp_path)
    agent = FakeAgent(["ANSWER: flag{runner_wrong}"])
    runner = _runner(tmp_path, adapter, agent)

    run = asyncio_run(runner.run(instances=[adapter.instances[0]]))

    result = run.results[0]
    assert result.status == "failed"
    assert result.success is False
    assert result.score == 0.0
    assert adapter.graded[0].value == "flag{runner_wrong}"
    log = (tmp_path / "run" / "one" / "agent.log").read_text(encoding="utf-8")
    assert EXPECTED not in log
    assert "flag{runner_wrong}" not in log


def test_open_failure_does_not_block_other_instances(tmp_path: Path) -> None:
    adapter = FakeAdapter(tmp_path, fail_open={"one"})
    agent = FakeAgent(["ANSWER: flag{runner_expected}", "ANSWER: flag{runner_expected}"])
    runner = _runner(tmp_path, adapter, agent)

    run = asyncio_run(runner.run())

    assert [item.status for item in run.results] == ["open_failed", "succeeded"]
    assert adapter.opened == ["two"]
    assert adapter.closed == ["two"]


def test_agent_failure_still_closes_and_records(tmp_path: Path) -> None:
    adapter = FakeAdapter(tmp_path)

    async def failing_agent(*args, **kwargs):
        raise RuntimeError("backend exploded")

    runner = _runner(tmp_path, adapter, failing_agent)

    run = asyncio_run(runner.run(instances=[adapter.instances[0]]))

    assert run.results[0].status == "agent_failed"
    assert "backend exploded" in run.results[0].error
    assert adapter.closed == ["one"]


def test_no_flag_and_grade_error_are_distinct(tmp_path: Path) -> None:
    adapter = FakeAdapter(tmp_path)
    agent = FakeAgent(["I could not solve it", "ANSWER: flag{runner_expected}"])
    runner = _runner(tmp_path, adapter, agent)

    run = asyncio_run(runner.run())

    assert run.results[0].status == "no_flag"
    assert run.results[0].extracted is False
    assert run.results[1].status == "succeeded"

    adapter = FakeAdapter(tmp_path, grade_error={"one"})
    agent = FakeAgent(["ANSWER: flag{runner_expected}"])
    runner = _runner(tmp_path / "grade", adapter, agent)
    run = asyncio_run(runner.run(instances=[adapter.instances[0]]))
    assert run.results[0].status == "grade_failed"
    assert "grade failed" in run.results[0].error
    assert adapter.closed == ["one"]


def test_cleanup_failure_does_not_mask_a_result(tmp_path: Path) -> None:
    adapter = FakeAdapter(tmp_path, fail_close={"one"})
    agent = FakeAgent(["ANSWER: flag{runner_expected}"])
    runner = _runner(tmp_path, adapter, agent)

    run = asyncio_run(runner.run(instances=[adapter.instances[0]]))

    assert run.results[0].status == "succeeded"
    assert "cleanup failed" in run.results[0].cleanup_error


def test_capture_trajectory_is_passed_and_scrubbed(tmp_path: Path) -> None:
    adapter = FakeAdapter(tmp_path)
    agent = FakeAgent(["ANSWER: flag{runner_expected}"])
    runner = _runner(tmp_path, adapter, agent, capture_trajectory=True)

    run = asyncio_run(runner.run(instances=[adapter.instances[0]]))

    assert run.results[0].status == "succeeded"
    assert agent.calls[0]["trajectory"] is True
    assert agent.calls[0]["config"].trajectory_enabled is True
    trajectory = tmp_path / "run" / "trajectories" / "one" / "agent.json"
    assert trajectory.is_file()
    assert EXPECTED not in trajectory.read_text(encoding="utf-8")
    assert "[REDACTED]" in trajectory.read_text(encoding="utf-8")


def test_preflight_failure_raises_before_any_instance(tmp_path: Path) -> None:
    class Broken(FakeAdapter):
        def preflight(self):
            raise RuntimeError("vpn down")

    runner = _runner(tmp_path, Broken(tmp_path), FakeAgent([]))
    with pytest.raises(BenchRunError, match="preflight failed"):
        asyncio_run(runner.run())


def test_summary_counts_errors_separately(tmp_path: Path) -> None:
    adapter = FakeAdapter(tmp_path, fail_open={"two"})
    agent = FakeAgent(["ANSWER: flag{runner_expected}"])
    runner = _runner(tmp_path, adapter, agent)

    run = asyncio_run(runner.run())

    summary = run.summary()
    assert summary["total"] == 2
    assert summary["succeeded"] == 1
    assert summary["failed"] == 0
    assert summary["errors"] == 1


def asyncio_run(coroutine):
    import asyncio

    return asyncio.run(coroutine)
