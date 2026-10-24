"""CLI tests for ``code-auditor --validate-trajectory``."""

from __future__ import annotations

import json
from pathlib import Path

from code_auditor.__main__ import _validate_trajectories


def _minimal_document(steps: list[dict[str, object]]) -> dict[str, object]:
    return {
        "schema_version": "ATIF-v1.7",
        "agent": {"name": "code-auditor", "version": "0.1.0"},
        "steps": steps,
    }


def test_cli_validator_reports_dangling_child_reference(tmp_path: Path, capsys) -> None:
    root = tmp_path / "trajectories"
    (root / "stage5-pocs" / "H-1").mkdir(parents=True)
    (root / "stage5-pocs" / "H-1" / "agent.json").write_text(
        json.dumps(_minimal_document([{"step_id": 1, "source": "user", "message": "go"}])),
        encoding="utf-8",
    )
    root_document = _minimal_document(
        [
            {"step_id": 1, "source": "user", "message": "go"},
            {
                "step_id": 2,
                "source": "agent",
                "message": "",
                "llm_call_count": 0,
                "tool_calls": [
                    {
                        "tool_call_id": "d",
                        "function_name": "delegate_subagent",
                        "arguments": {},
                    }
                ],
                "observation": {
                    "results": [
                        {
                            "source_call_id": "d",
                            "content": "summary",
                            "subagent_trajectory_ref": [
                                {"trajectory_path": "stage5-pocs/H-1/agent.json"}
                            ],
                        }
                    ]
                },
            },
        ]
    )
    (root / "trajectory.json").write_text(json.dumps(root_document), encoding="utf-8")
    assert _validate_trajectories(str(tmp_path)) is True
    capsys.readouterr()

    (root / "stage5-pocs" / "H-1" / "agent.json").unlink()
    assert _validate_trajectories(str(tmp_path)) is False
    report = json.loads(capsys.readouterr().out)
    assert report["invalid"] == 1
    assert any(
        "does not exist" in problem
        for entry in report["files"]
        for problem in entry["problems"]
    )

