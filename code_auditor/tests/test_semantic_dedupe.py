from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest

from code_auditor.checkpoint import CheckpointManager
from code_auditor.config import AuditConfig
from code_auditor.disclosures import build_dedupe_key
from code_auditor.semantic_dedupe import (
    DedupeCandidate,
    candidate_from_finding,
    filter_semantic_duplicates,
    write_dedupe_report,
)
from code_auditor.stages import stage4


def _finding(title: str, trigger: str) -> dict[str, object]:
    return {
        "title": title,
        "location": "src/parser.c:parse_packet",
        "data_flow_trace": {
            "entry_point": "src/net.c:read_packet",
            "sink": "memcpy(dst, src, len)",
        },
        "cwe_id": ["CWE-191"],
        "vulnerability_class": ["integer underflow"],
        "trigger": trigger,
        "summary": f"{title} summary",
    }


def _config(tmp_path: Path) -> AuditConfig:
    target = tmp_path / "target"
    output = target / "audit-output"
    target.mkdir(parents=True)
    output.mkdir()
    return AuditConfig(target=str(target), output_dir=str(output), max_parallel=2)


def test_semantic_dedupe_filters_exact_key_without_agent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = _config(tmp_path)
    finding = _finding("A", "same trigger")
    key = build_dedupe_key(finding, "")
    candidate = candidate_from_finding("H-01", finding, repo_url="")

    async def unexpected(*_args: object, **_kwargs: object) -> str:
        pytest.fail("exact duplicate should not call the model")

    monkeypatch.setattr("code_auditor.semantic_dedupe.run_agent", unexpected)
    kept, decisions = asyncio.run(
        filter_semantic_duplicates(
            [candidate],
            ({"dedupe_key": key, "title": "Known"},),
            config,
            log_dir=str(tmp_path / "logs"),
            label="Stage 4",
        )
    )

    assert kept == []
    assert decisions[0].decision == "duplicate"
    assert decisions[0].matched_dedupe_key == key


def test_semantic_dedupe_prefers_same_project_inventory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = _config(tmp_path)
    finding = _finding("A", "same trigger")
    key = build_dedupe_key(finding, "")
    candidate = candidate_from_finding("H-01", finding, repo_url="")
    prompts: list[str] = []

    async def compare(prompt: str, *_args: object, **_kwargs: object) -> str:
        prompts.append(prompt)
        return json.dumps(
            {
                "decision": "new",
                "matched_dedupe_key": "",
                "reason": "different project",
            }
        )

    kept, decisions = asyncio.run(
        filter_semantic_duplicates(
            [candidate],
            (
                {"project": "target", "dedupe_key": "sha256:" + "b" * 64,
                 "title": "Same-project unrelated"},
                {"project": "other-project", "dedupe_key": key,
                 "title": "Cross-project exact key"},
            ),
            config,
            log_dir=str(tmp_path / "logs"),
            label="Stage 4",
            run_agent_fn=compare,
        )
    )

    assert kept == [candidate]
    assert decisions[0].decision == "new"
    assert prompts and "Cross-project exact key" not in prompts[0]
    assert "Same-project unrelated" in prompts[0]


def test_semantic_dedupe_compares_current_batch_and_writes_report(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = _config(tmp_path)
    first = candidate_from_finding("H-01", _finding("A", "trigger one"), repo_url="")
    second = candidate_from_finding("H-02", _finding("B", "trigger two"), repo_url="")
    prompts: list[str] = []

    async def compare(prompt: str, *_args: object, **_kwargs: object) -> str:
        prompts.append(prompt)
        return json.dumps(
            {
                "decision": "duplicate",
                "matched_dedupe_key": first.dedupe_key,
                "reason": "same root cause",
            }
        )

    kept, decisions = asyncio.run(
        filter_semantic_duplicates(
            [first, second],
            (),
            config,
            log_dir=str(tmp_path / "logs"),
            label="Stage 4",
            run_agent_fn=compare,
        )
    )
    report = tmp_path / "dedupe.json"
    write_dedupe_report(str(report), decisions)

    assert kept == [first]
    assert [item.decision for item in decisions] == ["new", "duplicate"]
    assert len(prompts) == 1
    assert first.dedupe_key in prompts[0]
    payload = json.loads(report.read_text(encoding="utf-8"))
    assert payload["kept"] == 1
    assert payload["filtered"] == 1


def test_semantic_dedupe_fails_open(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    config = _config(tmp_path)
    first = candidate_from_finding("H-01", _finding("A", "trigger one"), repo_url="")
    second = candidate_from_finding("H-02", _finding("B", "trigger two"), repo_url="")

    async def broken(*_args: object, **_kwargs: object) -> str:
        return "not json"

    kept, decisions = asyncio.run(
        filter_semantic_duplicates(
            [first, second],
            (),
            config,
            log_dir=str(tmp_path / "logs"),
            label="Stage 4",
            run_agent_fn=broken,
        )
    )

    assert kept == [first, second]
    assert [item.decision for item in decisions] == ["new", "new"]


def test_stage4_semantic_dedupe_moves_duplicate_pending_file(tmp_path: Path) -> None:
    config = _config(tmp_path)
    finding = _finding("A", "same trigger")
    pending = Path(config.output_dir) / "stage4-vulnerabilities" / "_pending"
    pending.mkdir(parents=True)
    first = pending / "AU-1-F-01.json"
    second = pending / "AU-2-F-01.json"
    first.write_text(json.dumps(finding), encoding="utf-8")
    second.write_text(json.dumps(finding), encoding="utf-8")

    kept = asyncio.run(stage4._semantic_dedupe_pending([str(first), str(second)], config))

    assert kept == [str(first)]
    duplicates = Path(config.output_dir) / "stage4-vulnerabilities" / "_duplicates"
    assert (duplicates / second.name).is_file()
    assert not second.exists()
    report = Path(config.output_dir) / "stage4-vulnerabilities" / "semantic-dedupe.json"
    assert json.loads(report.read_text(encoding="utf-8"))["filtered"] == 1
