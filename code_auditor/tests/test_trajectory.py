"""ATIF v1.7 trajectory capture tests.

The assertions here mirror the constraints the Harbor RFC (and the published
``atif`` Pydantic models) impose on a trajectory document, plus the mapping
from the two SDK event streams CodeAuditor records.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from code_auditor import agent as agent_module
from code_auditor.config import AuditConfig
from code_auditor.orchestrator import _finish_run_trajectory, _start_run_trajectory
from code_auditor.trajectory import (
    SCHEMA_VERSION,
    TrajectoryRecorder,
    child_trajectory_path,
    redact_text,
    validate_trajectory,
)

# --------------------------------------------------------------------------- #
# fakes: the recorder dispatches on ``type(message).__name__``
# --------------------------------------------------------------------------- #


class TextBlock:
    def __init__(self, text: str) -> None:
        self.text = text


class ThinkingBlock:
    def __init__(self, thinking: str) -> None:
        self.thinking = thinking


class ToolUseBlock:
    def __init__(self, block_id: str, name: str, tool_input: object) -> None:
        self.id = block_id
        self.name = name
        self.input = tool_input


class ToolResultBlock:
    def __init__(self, tool_use_id: str, content: object, is_error: bool = False) -> None:
        self.tool_use_id = tool_use_id
        self.content = content
        self.is_error = is_error


class AssistantMessage:
    def __init__(self, content: list[object]) -> None:
        self.content = content


class UserMessage:
    def __init__(self, content: list[object]) -> None:
        self.content = content


class SystemMessage:
    def __init__(self, subtype: str = "init") -> None:
        self.subtype = subtype


class ResultMessage:
    def __init__(
        self,
        *,
        usage: dict[str, object] | None = None,
        cost: float | None = 0.01,
        error: bool = False,
    ) -> None:
        self.usage = usage or {
            "input_tokens": 100,
            "output_tokens": 20,
            "cache_read_input_tokens": 900,
            "cache_creation_input_tokens": 50,
        }
        self.total_cost_usd = cost
        self.num_turns = 3
        self.duration_ms = 1200
        self.is_error = error


class CodexItem:
    def __init__(self, **values: object) -> None:
        self.__dict__.update(values)


class CodexPayload:
    def __init__(self, **values: object) -> None:
        self.__dict__.update(values)


class CodexEvent:
    def __init__(self, method: str, payload: CodexPayload) -> None:
        self.method = method
        self.payload = payload


# --------------------------------------------------------------------------- #
# validator
# --------------------------------------------------------------------------- #


def _minimal_document(steps: list[dict[str, object]]) -> dict[str, object]:
    return {
        "schema_version": SCHEMA_VERSION,
        "agent": {"name": "code-auditor", "version": "0.1.0"},
        "steps": steps,
    }


def test_validator_accepts_a_minimal_document() -> None:
    document = _minimal_document(
        [
            {"step_id": 1, "source": "system", "message": "role"},
            {"step_id": 2, "source": "user", "message": "task"},
            {
                "step_id": 3,
                "source": "agent",
                "message": "reading",
                "tool_calls": [
                    {"tool_call_id": "t1", "function_name": "Read", "arguments": {"p": "a.c"}}
                ],
                "observation": {"results": [{"source_call_id": "t1", "content": "x"}]},
                "metrics": {"prompt_tokens": 10},
            },
        ]
    )
    assert validate_trajectory(document) == []


@pytest.mark.parametrize(
    ("mutate", "expected"),
    [
        (lambda d: d["steps"][1].update(step_id=3), "sequential"),
        (lambda d: d["steps"][1].update(tool_calls=[]), "only valid on source='agent'"),
        (
            lambda d: d["steps"][2]["observation"]["results"][0].update(source_call_id="nope"),
            "does not match",
        ),
        (lambda d: d.update(schema_version="ATIF-v1.0"), "schema_version"),
        (lambda d: d["steps"][2].update(llm_call_count=0), "must be absent"),
        (lambda d: d["steps"][2].update(extra_field=1), "unknown fields"),
        (
            lambda d: d["steps"][2].update(reasoning_effort=True),
            "string or number",
        ),
        (
            lambda d: d["steps"][2]["metrics"].update(prompt_tokens="ten"),
            "prompt_tokens must be an integer",
        ),
        (
            lambda d: d["steps"][2]["metrics"].update(secret="x"),
            "unknown fields",
        ),
        (
            lambda d: d["steps"][2]["observation"]["results"][0].update(extra_field=1),
            "unknown fields",
        ),
    ],
)
def test_validator_rejects_constraint_violations(mutate, expected) -> None:
    document = _minimal_document(
        [
            {"step_id": 1, "source": "system", "message": "role"},
            {"step_id": 2, "source": "user", "message": "task"},
            {
                "step_id": 3,
                "source": "agent",
                "message": "reading",
                "tool_calls": [
                    {"tool_call_id": "t1", "function_name": "Read", "arguments": {"p": "a.c"}}
                ],
                "observation": {"results": [{"source_call_id": "t1", "content": "x"}]},
                "metrics": {"prompt_tokens": 10},
            },
        ]
    )
    mutate(document)
    problems = validate_trajectory(document)
    assert any(expected in problem for problem in problems)


# --------------------------------------------------------------------------- #
# Claude mapping
# --------------------------------------------------------------------------- #


def test_claude_messages_map_to_system_user_and_agent_steps(tmp_path: Path) -> None:
    recorder = TrajectoryRecorder(
        session_id="run-1", model_name="claude-sonnet-4-6", blob_dir=tmp_path / "blobs"
    )
    recorder.system("You are CodeAuditor.")
    recorder.user("Audit /tmp/target")
    recorder.on_claude_message(SystemMessage())
    recorder.on_claude_message(
        AssistantMessage(
            [
                ThinkingBlock("the parser is reachable"),
                TextBlock("Let me read the parser."),
                ToolUseBlock("t1", "Read", {"file_path": "parser.c"}),
            ]
        )
    )
    recorder.on_claude_message(
        UserMessage([ToolResultBlock("t1", "int parse(char *s) { ... }")])
    )
    recorder.on_claude_message(ResultMessage())
    recorder.finish()

    document = recorder.to_dict()
    assert validate_trajectory(document) == []
    sources = [step["source"] for step in document["steps"]]
    assert sources == ["system", "user", "system", "agent"]

    agent_step = document["steps"][3]
    assert agent_step["message"] == "Let me read the parser."
    assert agent_step["reasoning_content"] == "the parser is reachable"
    assert agent_step["model_name"] == "claude-sonnet-4-6"
    assert agent_step["tool_calls"][0]["tool_call_id"] == "t1"
    assert agent_step["tool_calls"][0]["arguments"] == {"file_path": "parser.c"}
    # The tool result lands on the step that declared the call.
    assert agent_step["observation"]["results"][0]["source_call_id"] == "t1"
    # ATIF: prompt tokens include cached input; cached is a subset.
    assert agent_step["metrics"]["prompt_tokens"] == 1050
    assert agent_step["metrics"]["cached_tokens"] == 900
    assert agent_step["metrics"]["cost_usd"] == pytest.approx(0.01)
    assert agent_step["metrics"]["extra"]["num_turns"] == 3


def test_tool_result_without_a_known_call_is_kept_as_its_own_step() -> None:
    recorder = TrajectoryRecorder()
    recorder.tool_result("ghost", "late output")
    document = recorder.to_dict()
    steps = document["steps"]
    assert len(steps) == 1
    assert steps[0]["llm_call_count"] == 0
    assert steps[0]["extra"]["orphan_result"] is True
    result = steps[0]["observation"]["results"][0]
    assert result["content"] == "late output"
    # ATIF only allows source_call_id when the call is in the same step.
    assert "source_call_id" not in result
    assert result["extra"]["unknown_source_call_id"] == "ghost"
    assert validate_trajectory(document) == []


def test_error_result_marks_the_result_and_notes_the_run() -> None:
    recorder = TrajectoryRecorder()
    recorder.on_claude_message(AssistantMessage([TextBlock("attempt")]))
    recorder.on_claude_message(ResultMessage(error=True))
    recorder.finish()
    document = recorder.to_dict()
    assert "agent reported an error result" in document["notes"]
    assert validate_trajectory(document) == []


# --------------------------------------------------------------------------- #
# Codex mapping
# --------------------------------------------------------------------------- #


def test_codex_items_map_to_tool_steps_and_a_final_message() -> None:
    recorder = TrajectoryRecorder(model_name="gpt-5.4")
    recorder.user("exploit")
    recorder.on_codex_event(
        CodexEvent(
            "item/started",
            CodexPayload(item=CodexItem(id="i1", type="commandExecution", command=["bash", "poc.sh"])),
        )
    )
    recorder.on_codex_event(
        CodexEvent(
            "item/completed",
            CodexPayload(
                item=CodexItem(
                    id="i1",
                    type="commandExecution",
                    aggregatedOutput="boom: heap-buffer-overflow",
                )
            ),
        )
    )
    recorder.on_codex_event(
        CodexEvent("item/agentMessage/delta", CodexPayload(delta="The PoC crashed the parser."))
    )
    recorder.on_codex_event(
        CodexEvent(
            "turn/completed",
            CodexPayload(
                turn=CodexItem(
                    id="t1",
                    usage={
                        "inputTokens": 30,
                        "outputTokens": 7,
                        "cachedInputTokens": 10,
                        "reasoningOutputTokens": 2,
                    },
                )
            ),
        )
    )
    recorder.finish()

    document = recorder.to_dict()
    assert validate_trajectory(document) == []
    tool_step = document["steps"][1]
    assert tool_step["tool_calls"][0]["function_name"] == "shell"
    assert tool_step["tool_calls"][0]["arguments"] == {"command": ["bash", "poc.sh"]}
    assert tool_step["observation"]["results"][0]["content"].startswith("boom")
    message_step = document["steps"][2]
    assert message_step["message"] == "The PoC crashed the parser."
    assert message_step["metrics"]["prompt_tokens"] == 40
    assert message_step["metrics"]["extra"]["reasoning_tokens"] == 2


# --------------------------------------------------------------------------- #
# redaction, spilling, merging
# --------------------------------------------------------------------------- #


def test_credentials_are_redacted_everywhere(tmp_path: Path) -> None:
    recorder = TrajectoryRecorder(blob_dir=tmp_path / "blobs")
    recorder.user("use sk-abcdefgh12345678 to call out")
    recorder.agent_step(
        message="running",
        tool_calls=[
            {
                "tool_call_id": "c1",
                "function_name": "shell",
                "arguments": {"cmd": "export KEY=sk-abcdefgh12345678"},
            }
        ],
    )
    recorder.tool_result("c1", "ANTHROPIC_AUTH_TOKEN=sk-abcdefgh12345678")
    document = recorder.to_dict()
    serialized = json.dumps(document)
    assert "sk-abcdefgh12345678" not in serialized
    assert document["steps"][1]["tool_calls"][0]["arguments"]["cmd"].endswith("[REDACTED]")
    assert validate_trajectory(document) == []


def test_oversized_result_spills_to_a_blob(tmp_path: Path) -> None:
    recorder = TrajectoryRecorder(blob_dir=tmp_path / "blobs", max_inline_bytes=64)
    recorder.agent_step(tool_calls=[{"tool_call_id": "c", "function_name": "shell", "arguments": {}}])
    recorder.tool_result("c", "A" * 4096)
    document = recorder.to_dict()
    result = document["steps"][0]["observation"]["results"][0]
    assert result["extra"]["truncated"] is True
    assert result["extra"]["bytes"] == 4096
    blob = tmp_path / result["extra"]["blob"]
    assert blob.is_file()
    assert blob.read_text(encoding="utf-8") == "A" * 4096
    assert len(result["content"]) < 4096
    assert validate_trajectory(document) == []


def test_reopening_a_document_appends_a_repair_attempt(tmp_path: Path) -> None:
    path = tmp_path / "agent.json"
    first = TrajectoryRecorder()
    first.user("find bugs")
    first.on_claude_message(AssistantMessage([TextBlock("not json")]))
    first.finish()
    first.write(path)

    second = TrajectoryRecorder.load(path)
    assert second is not None
    second.user("repair: return JSON")
    second.on_claude_message(AssistantMessage([TextBlock("[]")]))
    second.finish()
    second.write(path)

    document = json.loads(path.read_text(encoding="utf-8"))
    assert [step["step_id"] for step in document["steps"]] == [1, 2, 3, 4]
    assert validate_trajectory(document) == []


def test_invalid_documents_are_written_as_invalid_instead_of_published(
    tmp_path: Path,
) -> None:
    recorder = TrajectoryRecorder(agent_name="")
    recorder.finish()
    path = tmp_path / "code-auditor-invalid-trajectory.json"
    written = recorder.write(path)
    try:
        assert written.name.endswith(".invalid.json")
        assert not path.exists()
    finally:
        written.unlink(missing_ok=True)


# --------------------------------------------------------------------------- #
# paths and run-level document
# --------------------------------------------------------------------------- #


def test_child_path_mirrors_the_logical_log_location(tmp_path: Path) -> None:
    config = AuditConfig(target="/src", output_dir=str(tmp_path / "out"))
    config.trajectory_root_dir = str(tmp_path / "out" / "trajectories")
    path = child_trajectory_path(
        config, str(tmp_path / "out" / "stage5-pocs" / "H-12" / "agent.log")
    )
    assert path == tmp_path / "out" / "trajectories" / "stage5-pocs" / "H-12" / "agent.json"


def test_child_path_uses_the_run_root_for_a_sandbox_scratch_config(tmp_path: Path) -> None:
    """Stage 5/6 run with ``output_dir`` inside a disposable scratch tree."""
    scratch = tmp_path / "scratch"
    config = AuditConfig(target="/src", output_dir=str(scratch))
    config.trajectory_root_dir = str(tmp_path / "out" / "trajectories")
    path = child_trajectory_path(config, str(scratch / "stage5-pocs" / "H-12" / "agent.log"))
    assert path == tmp_path / "out" / "trajectories" / "stage5-pocs" / "H-12" / "agent.json"


def test_run_level_document_references_child_trajectories(tmp_path: Path) -> None:
    config = AuditConfig(target="/src", output_dir=str(tmp_path / "out"))
    config.usage_stats.update(
        {
            "agent_calls": 2,
            "input_tokens": 1000,
            "output_tokens": 200,
            "cache_read_input_tokens": 300,
            "cache_creation_input_tokens": 50,
            "cost_usd": 0.25,
        }
    )
    root = _start_run_trajectory(config)
    assert root is not None
    root.add_subagent(
        "stage5-pocs/H-12/agent.json",
        label="H-12",
        summary="12 steps",
        trajectory_id="child-1",
    )
    _finish_run_trajectory(config, root)

    path = tmp_path / "out" / "trajectories" / "trajectory.json"
    document = json.loads(path.read_text(encoding="utf-8"))
    assert validate_trajectory(document) == []
    assert document["session_id"].startswith("run-")
    assert document["final_metrics"]["total_prompt_tokens"] == 1350
    assert document["final_metrics"]["total_cached_tokens"] == 300
    assert document["final_metrics"]["total_cost_usd"] == pytest.approx(0.25)

    delegation = document["steps"][-1]
    assert delegation["llm_call_count"] == 0
    ref = delegation["observation"]["results"][0]["subagent_trajectory_ref"][0]
    assert ref["trajectory_path"] == "stage5-pocs/H-12/agent.json"
    assert ref["trajectory_id"] == "child-1"
    assert config.trajectory_root is None


def test_trajectory_can_be_disabled(tmp_path: Path) -> None:
    config = AuditConfig(
        target="/src", output_dir=str(tmp_path / "out"), trajectory_enabled=False
    )
    assert _start_run_trajectory(config) is None
    assert not (tmp_path / "out" / "trajectories").exists()


# --------------------------------------------------------------------------- #
# end-to-end through run_agent
# --------------------------------------------------------------------------- #


def test_run_agent_writes_a_child_trajectory_and_registers_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class FakeOptions:
        def __init__(self, **values: object) -> None:
            self.__dict__.update(values)

    async def fake_query(*, prompt: str, options: FakeOptions):
        yield AssistantMessage([TextBlock("looking")])
        yield AssistantMessage([ToolUseBlock("t1", "Read", {"file_path": "a.c"})])
        yield UserMessage([ToolResultBlock("t1", "int main(void){}")])
        yield ResultMessage()

    monkeypatch.setattr(
        agent_module, "_load_claude_sdk", lambda: (FakeOptions, fake_query)
    )

    output_dir = tmp_path / "out"
    poc_dir = output_dir / "stage5-pocs" / "H-12"
    poc_dir.mkdir(parents=True)
    config = AuditConfig(
        target=str(tmp_path / "src"),
        output_dir=str(output_dir),
        agent_timeout_seconds=None,
    )
    root = _start_run_trajectory(config)
    assert root is not None

    asyncio_run(
        agent_module.run_agent(
            "write a PoC",
            config,
            cwd=config.target,
            log_file=str(poc_dir / "agent.log"),
        )
    )

    child = output_dir / "trajectories" / "stage5-pocs" / "H-12" / "agent.json"
    assert child.is_file()
    document = json.loads(child.read_text(encoding="utf-8"))
    assert validate_trajectory(document) == []
    assert document["steps"][0]["source"] == "user"
    assert document["steps"][0]["message"] == "write a PoC"
    assert document["extra"]["status"] == "completed"

    _finish_run_trajectory(config, root)
    run_document = json.loads(
        (output_dir / "trajectories" / "trajectory.json").read_text(encoding="utf-8")
    )
    refs = [
        result["subagent_trajectory_ref"][0]["trajectory_path"]
        for step in run_document["steps"]
        for result in (step.get("observation") or {}).get("results", [])
        if result.get("subagent_trajectory_ref")
    ]
    assert "stage5-pocs/H-12/agent.json" in refs


def test_run_agent_skips_capture_when_log_file_is_absent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class FakeOptions:
        def __init__(self, **values: object) -> None:
            self.__dict__.update(values)

    async def fake_query(*, prompt: str, options: FakeOptions):
        yield AssistantMessage([TextBlock("ok")])
        yield ResultMessage()

    monkeypatch.setattr(agent_module, "_load_claude_sdk", lambda: (FakeOptions, fake_query))

    config = AuditConfig(
        target=str(tmp_path / "src"),
        output_dir=str(tmp_path / "out"),
        agent_timeout_seconds=None,
    )
    asyncio_run(agent_module.run_agent("prompt", config, cwd=config.target))
    assert not (tmp_path / "out" / "trajectories").exists()


def asyncio_run(coroutine):
    import asyncio

    return asyncio.run(coroutine)


def test_run_audit_publishes_the_root_document_even_when_a_stage_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A failed audit still leaves an inspectable run-level trajectory."""
    import asyncio

    from code_auditor import orchestrator

    async def failing_setup(config: AuditConfig) -> None:
        raise RuntimeError("stage 0 failed")

    monkeypatch.setattr(orchestrator, "run_setup", failing_setup)
    config = AuditConfig(target=str(tmp_path / "src"), output_dir=str(tmp_path / "out"))

    with pytest.raises(RuntimeError):
        asyncio.run(orchestrator.run_audit(config))

    path = tmp_path / "out" / "trajectories" / "trajectory.json"
    assert path.is_file()
    document = json.loads(path.read_text(encoding="utf-8"))
    assert validate_trajectory(document) == []
    assert document["extra"]["run_kind"] == "audit"


def test_metrics_never_land_on_a_deterministic_step() -> None:
    recorder = TrajectoryRecorder()
    recorder.deterministic(message="launch container")
    recorder.record_usage({"input_tokens": 10, "output_tokens": 2})  # dropped
    recorder.finish()
    document = recorder.to_dict()
    assert document["steps"][0]["llm_call_count"] == 0
    assert "metrics" not in document["steps"][0]
    assert validate_trajectory(document) == []


def test_repeated_usage_reports_replace_instead_of_accumulating(tmp_path: Path) -> None:
    recorder = TrajectoryRecorder()
    recorder.on_claude_message(AssistantMessage([TextBlock("turn")]))
    recorder.record_usage({"input_tokens": 100, "output_tokens": 10})
    # A cumulative re-report (Codex sends updates as the turn progresses).
    recorder.record_usage({"input_tokens": 150, "output_tokens": 20})
    recorder.finish()
    metrics = recorder.to_dict()["steps"][0]["metrics"]
    assert metrics["prompt_tokens"] == 150
    assert metrics["completion_tokens"] == 20
    assert recorder.to_dict()["final_metrics"]["total_prompt_tokens"] == 150


def test_child_path_cannot_escape_the_trajectory_root(tmp_path: Path) -> None:
    config = AuditConfig(target="/src", output_dir=str(tmp_path / "out"))
    config.trajectory_root_dir = str(tmp_path / "out" / "trajectories")
    path = child_trajectory_path(config, None, label="../../etc/passwd")
    assert (tmp_path / "out" / "trajectories") in path.parents
    assert ".." not in path.parts


def test_dot_directories_are_preserved_in_child_paths(tmp_path: Path) -> None:
    """Stage 6 dedupe logs live under ``.dedupe-logs``."""
    config = AuditConfig(target="/src", output_dir=str(tmp_path / "out"))
    config.trajectory_root_dir = str(tmp_path / "out" / "trajectories")
    path = child_trajectory_path(
        config,
        str(tmp_path / "out" / "stage6-disclosures" / ".dedupe-logs" / "H-12.log"),
    )
    assert path == (
        tmp_path
        / "out"
        / "trajectories"
        / "stage6-disclosures"
        / ".dedupe-logs"
        / "H-12.json"
    )


def test_plain_string_assistant_content_is_recorded() -> None:
    class LegacyAssistantMessage:
        content = "legacy text payload"

    recorder = TrajectoryRecorder()
    recorder.on_claude_message(LegacyAssistantMessage())
    document = recorder.to_dict()
    assert document["steps"][0]["source"] == "agent"
    assert document["steps"][0]["message"] == "legacy text payload"
    assert validate_trajectory(document) == []


# --------------------------------------------------------------------------- #
# run-level lifecycle
# --------------------------------------------------------------------------- #


def test_resume_keeps_refs_children_and_token_totals(tmp_path: Path) -> None:
    """A resumed run must not drop checkpoints or previous usage."""
    output_dir = str(tmp_path / "out")
    first_config = AuditConfig(
        target="/src", output_dir=output_dir, resume=True
    )
    first_config.usage_stats.update(
        {"input_tokens": 100, "output_tokens": 10, "cache_read_input_tokens": 20, "cost_usd": 0.1}
    )
    root = _start_run_trajectory(first_config)
    assert root is not None
    root.add_subagent(
        "stage1-security-context/agent.json", label="stage1", trajectory_id="c1"
    )
    _finish_run_trajectory(first_config, root)
    root_path = tmp_path / "out" / "trajectories" / "trajectory.json"
    first = json.loads(root_path.read_text(encoding="utf-8"))

    # A child written by this run but never registered (process died first).
    child = tmp_path / "out" / "trajectories" / "stage5-pocs" / "H-09" / "agent.json"
    child.parent.mkdir(parents=True)
    child.write_text(
        json.dumps(
            {
                "schema_version": SCHEMA_VERSION,
                "session_id": first["session_id"],
                "trajectory_id": "c2",
                "agent": {"name": "code-auditor", "version": "0.1.0"},
                "steps": [
                    {"step_id": 1, "source": "user", "message": "go"},
                    {"step_id": 2, "source": "agent", "message": "done"},
                ],
            }
        ),
        encoding="utf-8",
    )

    second_config = AuditConfig(
        target="/src", output_dir=output_dir, resume=True
    )
    second_config.usage_stats.update({"input_tokens": 50, "output_tokens": 5})
    resumed = _start_run_trajectory(second_config)
    assert resumed is not None
    assert resumed.session_id == first["session_id"]
    _finish_run_trajectory(second_config, resumed)

    document = json.loads(root_path.read_text(encoding="utf-8"))
    assert validate_trajectory(document) == []
    paths = [
        ref["trajectory_path"]
        for step in document["steps"]
        for result in (step.get("observation") or {}).get("results", [])
        for ref in result.get("subagent_trajectory_ref", [])
    ]
    assert "stage1-security-context/agent.json" in paths
    assert "stage5-pocs/H-09/agent.json" in paths
    assert document["final_metrics"]["total_prompt_tokens"] == 170
    assert document["final_metrics"]["total_completion_tokens"] == 15
    assert document["final_metrics"]["total_cost_usd"] == pytest.approx(0.1)


def test_invalid_child_is_not_registered_with_the_run(tmp_path: Path) -> None:
    config = AuditConfig(target="/src", output_dir=str(tmp_path / "out"))
    root = _start_run_trajectory(config)
    assert root is not None
    recorder = TrajectoryRecorder(
        session_id=root.session_id,
        blob_dir=tmp_path / "out" / "trajectories" / "x" / "blobs",
    )
    recorder.user("u")
    # A non-agent step carrying tool_calls violates ATIF.
    recorder.steps[0]["tool_calls"] = [
        {"tool_call_id": "c", "function_name": "f", "arguments": {}}
    ]
    path = tmp_path / "out" / "trajectories" / "x" / "agent.json"

    agent_module._flush_trajectory(recorder, path, config, status="completed")

    assert (path.parent / "agent.invalid.json").is_file()
    assert not root.has_subagent("x/agent.json")


def test_a_repair_attempt_does_not_duplicate_the_parent_ref() -> None:
    recorder = TrajectoryRecorder()
    recorder.user("u")
    recorder.add_subagent("stage3-findings/logs/AU-1.json", label="logs", trajectory_id="c1")
    recorder.add_subagent("stage3-findings/logs/AU-1.json", label="logs", trajectory_id="c1")

    document = recorder.to_dict()
    refs = [
        ref["trajectory_path"]
        for step in document["steps"]
        for result in (step.get("observation") or {}).get("results", [])
        for ref in result.get("subagent_trajectory_ref", [])
    ]
    assert refs == ["stage3-findings/logs/AU-1.json"]
    assert document["steps"][-1]["extra"]["delegations"] == 2


def test_total_inline_budget_spills_later_results(tmp_path: Path) -> None:
    recorder = TrajectoryRecorder(
        max_inline_bytes=1000,
        max_total_inline_bytes=1500,
        blob_dir=tmp_path / "blobs",
    )
    recorder.user("u")
    for index in range(3):
        recorder.agent_step(
            message="",
            tool_calls=[
                {
                    "tool_call_id": f"c{index}",
                    "function_name": "shell",
                    "arguments": {"command": "build"},
                }
            ],
        )
        recorder.tool_result(f"c{index}", "A" * 800)

    results = [
        result
        for step in recorder.to_dict()["steps"]
        for result in (step.get("observation") or {}).get("results", [])
    ]
    assert results[0]["content"] == "A" * 800
    assert results[1]["content"] == "A" * 800
    assert results[2]["extra"]["inline_budget_exceeded"] is True
    assert results[2]["extra"]["blob"].startswith("blobs/")
    assert len(results[2]["content"]) < 1200


def test_environment_switch_disables_capture(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("CODE_AUDITOR_TRAJECTORY", "0")
    config = AuditConfig(target="/src", output_dir=str(tmp_path / "out"))
    assert config.trajectory_enabled is False
    assert _start_run_trajectory(config) is None
    assert not (tmp_path / "out" / "trajectories").exists()


def test_common_cloud_and_scm_credentials_are_redacted() -> None:
    text = (
        "AKIAIOSFODNN7EXAMPLE ghp_abcdefghijklmnopqrstuvwxyz0123456789 "
        "xoxb-1234567890-abcdefghij "
        "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA\n"
        "-----END RSA PRIVATE KEY-----"
    )
    redacted = redact_text(text)
    assert "AKIAIOSFODNN7EXAMPLE" not in redacted
    assert "ghp_" not in redacted
    assert "xoxb-" not in redacted
    assert "MIIEowIBAAKCAQEA" not in redacted
    assert redacted.count("[REDACTED]") >= 4
