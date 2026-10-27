"""Benchmark adapter tests (no network access)."""

from __future__ import annotations

import json

import pytest

from code_auditor.bench import (
    InstanceSpec,
    Submission,
    TSecBenchAdapter,
    benchmark_platform_capability,
    create,
    registered,
)
from code_auditor.bench.adapters.tsecbench import (
    TSecBenchClient,
    TSecBenchError,
)


class FakeTransport:
    def __init__(self, responses: list[tuple[int, object]]) -> None:
        self.responses = list(responses)
        self.calls: list[dict[str, object]] = []

    def __call__(self, method, url, headers, body, timeout):
        self.calls.append(
            {
                "method": method,
                "url": url,
                "headers": dict(headers),
                "body": json.loads(body) if body else None,
            }
        )
        status, payload = self.responses.pop(0)
        return status, json.dumps(payload).encode("utf-8")


class FakeClient:
    def __init__(self, challenges=None) -> None:
        self.challenges = list(
            challenges
            or [
                {
                    "unique_code": "C-1",
                    "description": "SQL injection to admin",
                    "difficulty": "easy",
                    "level": 1,
                    "total_score": 100,
                    "flag_count": 1,
                    "correct_flag_count": 0,
                    "is_completed": False,
                    "container_status": "available",
                    "container_addr": "10.0.0.5:8080",
                },
                {
                    "unique_code": "C-2",
                    "description": "done already",
                    "is_completed": True,
                    "container_status": "stopped",
                },
            ]
        )
        self.started: list[str] = []
        self.closed: list[str] = []
        self.submitted: list[tuple[str, str]] = []
        self.submit_result: dict[str, object] = {
            "correct": True,
            "awarded": 100,
            "cumulative_score": 100,
            "correct_flag_count": 1,
            "total_flag_count": 1,
            "matched_flag_index": 0,
        }
        self.submit_error: TSecBenchError | None = None

    def list_challenges(self):
        return list(self.challenges)

    def start_challenge(self, code):
        self.started.append(code)

    def submit_flag(self, code, flag):
        self.submitted.append((code, flag))
        if self.submit_error is not None:
            raise self.submit_error
        return dict(self.submit_result)

    def close_challenge(self, code):
        self.closed.append(code)


def _adapter(client, **options) -> TSecBenchAdapter:
    values: dict[str, object] = {"wait_seconds": 10, "poll_seconds": 1}
    values.update(options)
    return TSecBenchAdapter(client=client, **values)


def test_client_sends_token_and_uses_openapi_paths() -> None:
    transport = FakeTransport(
        [
            (200, {"challenges": []}),
            (200, {"ok": True}),
            (200, {"correct": True}),
        ]
    )
    client = TSecBenchClient(
        base_url="http://bench.local/",
        token="secret-token",
        transport=transport,
    )

    assert client.list_challenges() == []
    client.start_challenge("C-1")
    client.submit_flag("C-1", "FLAG{1}")

    assert transport.calls[0]["method"] == "GET"
    assert transport.calls[0]["url"] == "http://bench.local/openapi/v1/challenges"
    assert transport.calls[0]["headers"]["BENCHMARK_TOKEN"] == "secret-token"
    assert transport.calls[1]["url"].endswith(
        "/openapi/v1/challenges/start?unique_code=C-1"
    )
    assert transport.calls[2]["body"] == {"unique_code": "C-1", "flag": "FLAG{1}"}


def test_client_preflight_does_not_send_the_token() -> None:
    transport = FakeTransport([(200, {"status": "ok"})])
    client = TSecBenchClient(
        base_url="http://bench.local",
        token="secret-token",
        transport=transport,
    )

    client.preflight()

    call = transport.calls[0]
    assert call["url"] == "http://10.0.100.58"
    assert "BENCHMARK_TOKEN" not in call["headers"]


def test_client_preflight_rejects_a_degraded_tunnel() -> None:
    client = TSecBenchClient(
        base_url="http://bench.local",
        token="secret-token",
        transport=FakeTransport([(200, {"status": "down"})]),
    )
    with pytest.raises(TSecBenchError, match="preflight failed"):
        client.preflight()


def test_client_maps_api_errors_to_a_typed_exception() -> None:
    client = TSecBenchClient(
        base_url="http://bench.local",
        token="secret-token",
        transport=FakeTransport(
            [(409, {"error": {"code": "invalid_state", "message": "task over"}})]
        ),
    )
    with pytest.raises(TSecBenchError) as excinfo:
        client.start_challenge("C-1")
    assert excinfo.value.status == 409
    assert excinfo.value.code == "invalid_state"


def test_adapter_lists_open_tasks_and_skips_completed() -> None:
    client = FakeClient()
    adapter = _adapter(client)

    instances = adapter.list_instances()
    assert [instance.instance_id for instance in instances] == ["C-1"]
    assert instances[0].metadata["container_addr"] == "10.0.0.5:8080"
    assert adapter.list_instances(include_completed=True)[1].instance_id == "C-2"

    task = adapter.open_task(instances[0], wait=True)

    assert client.started == ["C-1"]
    assert task.target == "10.0.0.5:8080"
    assert task.scenario == "remote-target"
    assert "SQL injection to admin" in task.prompt
    assert "Never guess" in task.prompt
    assert "10.0.0.5:8080" in task.prompt


def test_adapter_waits_for_the_container_address(monkeypatch) -> None:
    client = FakeClient()
    now = [0.0]

    def clock() -> float:
        return now[0]

    def sleep(seconds: float) -> None:
        now[0] += seconds

    adapter = _adapter(
        client,
        wait_seconds=5,
        poll_seconds=1,
        clock=clock,
        sleep=sleep,
    )
    pending = dict(client.challenges[0], container_status="pending", container_addr="")
    ready = dict(client.challenges[0])
    client.challenges = [pending]
    original = client.list_challenges

    def list_challenges():
        if now[0] >= 1:
            client.challenges = [ready]
        return original()

    client.list_challenges = list_challenges  # type: ignore[assignment]

    task = adapter.open_task("C-1", wait=True)
    assert task.target == "10.0.0.5:8080"
    assert now[0] >= 1


def test_adapter_enforces_the_three_active_challenge_limit() -> None:
    challenges = [
        dict(
            {
                "unique_code": f"C-{index}",
                "description": "x",
                "container_status": "available",
                "container_addr": "10.0.0.1:80",
            }
        )
        for index in range(4)
    ]
    client = FakeClient(challenges)
    adapter = _adapter(client)
    for instance in adapter.list_instances()[:3]:
        adapter.open_task(instance, wait=False)

    with pytest.raises(TSecBenchError, match="at most 3 active"):
        adapter.open_task(adapter.list_instances()[3], wait=False)

    adapter.close(adapter.list_instances()[0])
    adapter.open_task(adapter.list_instances()[3], wait=False)
    assert client.closed == ["C-0"]


def test_adapter_releases_a_started_container_when_no_address_arrives() -> None:
    client = FakeClient()
    client.challenges = [
        dict(client.challenges[0], container_status="pending", container_addr="")
    ]
    adapter = _adapter(client, wait_seconds=0)
    with pytest.raises(TSecBenchError, match="no target address"):
        adapter.open_task("C-1", wait=False)
    assert client.closed == ["C-1"]


def test_adapter_grade_uses_the_server_verdict() -> None:
    client = FakeClient()
    adapter = _adapter(client)
    instance = adapter.list_instances()[0]

    outcome = adapter.grade(
        instance, Submission(instance_id="C-1", kind="flag", value="FLAG{1}")
    )

    assert outcome.success is True
    assert outcome.score == 100
    assert outcome.detail["matched_flag_index"] == 0
    assert client.submitted == [("C-1", "FLAG{1}")]


def test_adapter_rejects_empty_flags_and_surfaces_duplicates() -> None:
    client = FakeClient()
    adapter = _adapter(client)
    instance = adapter.list_instances()[0]

    empty = adapter.grade(
        instance, Submission(instance_id="C-1", kind="flag", value="  ")
    )
    assert empty.success is False
    assert empty.detail["error"] == "empty flag"

    client.submit_error = TSecBenchError("duplicate", status=409, code="duplicate")
    duplicate = adapter.grade(
        instance, Submission(instance_id="C-1", kind="flag", value="FLAG{1}")
    )
    assert duplicate.success is False
    assert duplicate.detail["duplicate"] is True


def test_registry_exposes_tsecbench_and_rejects_unknown_names() -> None:
    assert registered() == ["tsecbench"]
    client = FakeClient()
    adapter = create("tsecbench", client=client)
    assert isinstance(adapter, TSecBenchAdapter)
    assert adapter.list_instances()[0].instance_id == "C-1"
    with pytest.raises(KeyError, match="Unknown benchmark adapter"):
        create("nope")


def test_benchmark_platform_prerequisites_are_explicit() -> None:
    available = lambda command: f"/usr/bin/{command}"

    tsec = benchmark_platform_capability(
        "tsecbench", platform_name="windows", command_exists=available
    )
    assert tsec.available is True
    assert "VPN" in tsec.reason


def test_adapter_builds_an_instance_getter_for_task_metadata() -> None:
    adapter = _adapter(FakeClient())
    instance = InstanceSpec(
        benchmark="tsecbench",
        instance_id="C-9",
        metadata={"description": "x"},
    )
    assert adapter._code(instance) == "C-9"
