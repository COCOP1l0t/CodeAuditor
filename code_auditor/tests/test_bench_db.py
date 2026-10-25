"""Persistence tests for benchmark runs/results."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from code_auditor.db import RUN_DONE, RUN_RUNNING, AuditStore


def _store(tmp_path: Path) -> AuditStore:
    return AuditStore(str(tmp_path / "history.db"))


def test_benchmark_run_lifecycle_and_upsert(tmp_path: Path) -> None:
    store = _store(tmp_path)
    run_id = store.create_bench_run(
        benchmark="ctftiny",
        adapter="CTFTinyAdapter",
        repo_dir="/data/CTFTiny",
        output_dir=str(tmp_path / "run"),
        backend="claude",
        model="claude-test",
        started_at=100.0,
    )
    running, total = store.list_bench_runs()
    assert total == 1
    assert running[0]["id"] == run_id
    assert running[0]["status"] == RUN_RUNNING

    store.record_bench_result(
        run_id,
        {
            "instance_id": "pwn-baby",
            "benchmark": "ctftiny",
            "status": "succeeded",
            "success": True,
            "score": 50.0,
            "extracted": True,
            "submitted_length": 12,
            "detail": {"category": "pwn", "matched": True},
            "agent_log": "pwn-baby/agent.log",
            "duration_seconds": 3.5,
        },
    )
    store.record_bench_result(
        run_id,
        {
            "instance_id": "web-x",
            "benchmark": "ctftiny",
            "status": "failed",
            "success": False,
            "score": 0.0,
            "extracted": True,
            "submitted_length": 10,
            "error": "wrong flag",
        },
    )
    running_rows, _ = store.list_bench_runs()
    assert running_rows[0]["total_instances"] == 2
    # Re-recording the same instance replaces, never duplicates.
    store.record_bench_result(
        run_id,
        {
            "instance_id": "pwn-baby",
            "benchmark": "ctftiny",
            "status": "succeeded",
            "success": True,
            "score": 50.0,
            "extracted": True,
            "submitted_length": 12,
            "detail": {"category": "pwn", "matched": True, "revision": 2},
        },
    )
    store.finish_bench_run(
        run_id,
        status=RUN_DONE,
        ended_at=112.0,
        summary={"total": 2, "succeeded": 1, "failed": 1, "errors": 0, "score": 50.0},
    )

    runs, total = store.list_bench_runs()
    assert total == 1
    run = runs[0]
    assert run["status"] == RUN_DONE
    assert run["total_instances"] == 2
    assert run["succeeded"] == 1
    assert run["failed"] == 1
    assert run["score"] == 50.0
    assert run["duration_seconds"] == pytest.approx(12.0)
    assert run["success_rate"] == 0.5
    assert run["repo_dir"] == "/data/CTFTiny"

    detail = store.get_bench_run(run_id)
    assert detail is not None
    assert len(detail["results"]) == 2
    by_id = {item["instance_id"]: item for item in detail["results"]}
    assert by_id["pwn-baby"]["detail"]["revision"] == 2
    assert by_id["pwn-baby"]["success"] is True
    assert by_id["web-x"]["success"] is False


def test_list_bench_runs_filters_and_search(tmp_path: Path) -> None:
    store = _store(tmp_path)
    first = store.create_bench_run(
        benchmark="ctftiny", adapter="ctftiny", output_dir=str(tmp_path / "alpha"), started_at=1
    )
    second = store.create_bench_run(
        benchmark="cybench", adapter="cybench", output_dir=str(tmp_path / "bravo"), started_at=2
    )
    store.finish_bench_run(first, status=RUN_DONE, ended_at=3)

    runs, total = store.list_bench_runs(benchmark="cybench")
    assert total == 1 and runs[0]["id"] == second
    runs, total = store.list_bench_runs(status=RUN_DONE)
    assert total == 1 and runs[0]["id"] == first
    runs, total = store.list_bench_runs(query="cybench")
    assert total == 1 and runs[0]["id"] == second
    runs, total = store.list_bench_runs(query="bravo")
    assert total == 1 and runs[0]["id"] == second
    assert store.list_bench_runs(limit=1)[1] == 2

    with pytest.raises(ValueError):
        store.list_bench_runs(status="nope")


def test_finish_without_summary_aggregates_results(tmp_path: Path) -> None:
    store = _store(tmp_path)
    run_id = store.create_bench_run(
        benchmark="tsecbench", adapter="tsecbench", output_dir=str(tmp_path / "run"), started_at=10
    )
    store.record_bench_result(
        run_id,
        {"instance_id": "C-1", "status": "succeeded", "success": True, "score": 100},
    )
    store.record_bench_result(
        run_id, {"instance_id": "C-2", "status": "open_failed", "success": None}
    )
    store.finish_bench_run(run_id, status=RUN_DONE, ended_at=20)

    run = store.get_bench_run(run_id)
    assert run is not None
    assert run["total_instances"] == 2
    assert run["succeeded"] == 1
    assert run["failed"] == 0
    assert run["errors"] == 1
    assert run["score"] == 100.0
    assert run["duration_seconds"] == pytest.approx(10.0)


def test_bench_result_requires_a_known_run(tmp_path: Path) -> None:
    store = _store(tmp_path)
    with pytest.raises(KeyError):
        store.record_bench_result(999, {"instance_id": "x", "status": "failed"})
    with pytest.raises(ValueError):
        store.create_bench_run(benchmark="", adapter="x", output_dir=str(tmp_path))
    with pytest.raises(KeyError):
        store.finish_bench_run(999, status=RUN_DONE)


def test_detail_is_valid_json_even_after_bad_input(tmp_path: Path) -> None:
    store = _store(tmp_path)
    run_id = store.create_bench_run(
        benchmark="x", adapter="x", output_dir=str(tmp_path / "run")
    )
    store.record_bench_result(
        run_id, {"instance_id": "i", "status": "failed", "detail": "not-a-mapping"}
    )
    run = store.get_bench_run(run_id)
    assert run is not None
    assert run["results"][0]["detail"] == {}
    json.dumps(run)
