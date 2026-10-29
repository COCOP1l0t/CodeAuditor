from __future__ import annotations

from pathlib import Path

import pytest

from code_auditor.config import AuditConfig
from code_auditor.layout import stage1_paths, stage4_paths, stage_state_path
from code_auditor.orchestrator import _select_stage5_vulnerabilities
from code_auditor.stage_runtime import repair_until_valid, stage_span
from code_auditor.stage_state import StageStateStore, read_stage_state


def test_layout_paths_are_canonical(tmp_path: Path) -> None:
    assert stage1_paths(str(tmp_path))["record"] == str(
        tmp_path / "stage1-security-context" / "stage-1-security-context.json"
    )
    assert stage4_paths(str(tmp_path))["pending"] == str(
        tmp_path / "stage4-vulnerabilities" / "_pending"
    )
    assert stage_state_path(str(tmp_path)) == str(tmp_path / ".stage-state.json")


async def test_repair_until_valid_stops_after_success() -> None:
    valid = False
    repair_calls: list[str] = []

    def validator():
        return [] if valid else [object()]

    async def repair(prompt: str) -> None:
        nonlocal valid
        repair_calls.append(prompt)
        valid = True

    issues = await repair_until_valid(
        validator=validator,
        repair=repair,
        repair_prompt=lambda current: f"repair {len(current)}",
        max_attempts=2,
    )

    assert issues == []
    assert repair_calls == ["repair 1"]


async def test_stage_span_persists_done_state_and_progress(tmp_path: Path) -> None:
    class Reporter:
        def __init__(self) -> None:
            self.events: list[tuple] = []

        def begin_stage(self, stage: int, description: str) -> None:
            self.events.append(("begin", stage, description))

        def stage_progress(self, stage: int, **values) -> None:
            self.events.append(("progress", stage, values))

        def end_stage(self, stage: int) -> None:
            self.events.append(("end", stage))

    reporter = Reporter()
    store = StageStateStore(str(tmp_path))
    config = AuditConfig(target=str(tmp_path), output_dir=str(tmp_path))

    async with stage_span(
        config, reporter, store, 3, "Testing stage lifecycle"
    ) as progress:
        progress.update(items_done=2, items_total=4, detail="half")

    persisted = read_stage_state(str(tmp_path))
    assert persisted[3]["status"] == "done"
    assert persisted[3]["items_done"] == 2
    assert persisted[3]["items_total"] == 4
    assert reporter.events == [
        ("begin", 3, "Testing stage lifecycle"),
        ("progress", 3, {"items_done": 2, "items_total": 4, "detail": "half"}),
        ("end", 3),
    ]


def test_stage_state_resume_preserves_completed_timing(tmp_path: Path) -> None:
    store = StageStateStore(str(tmp_path))
    store.begin(1, "research")
    store.complete(1)
    before = read_stage_state(str(tmp_path))[1]

    resumed = StageStateStore(str(tmp_path))
    resumed.reset(preserve_completed=True)
    resumed.begin(1, "research again")
    resumed.complete(1)
    after = read_stage_state(str(tmp_path))[1]

    assert after["status"] == "done"
    assert after["started_at"] == before["started_at"]
    assert after["ended_at"] == before["ended_at"]


def test_stage5_priority_budget_sorts_and_caps(tmp_path: Path, monkeypatch) -> None:
    low = tmp_path / "M-01.json"
    high = tmp_path / "H-01.json"
    medium = tmp_path / "M-02.json"
    low.write_text('{"cvss_score": "5.3"}', encoding="utf-8")
    high.write_text('{"cvss_score": "8.3"}', encoding="utf-8")
    medium.write_text('{"cvss_score": "6.9"}', encoding="utf-8")
    monkeypatch.setenv("CODE_AUDITOR_MIN_STAGE5_CVSS", "6.0")
    monkeypatch.setenv("CODE_AUDITOR_MAX_STAGE5_VULNS", "1")

    selected = _select_stage5_vulnerabilities([str(low), str(medium), str(high)])

    assert selected == [str(high)]


def test_stage5_defaults_to_high_and_critical(
    tmp_path: Path, monkeypatch
) -> None:
    critical = tmp_path / "C-01.json"
    high = tmp_path / "H-01.json"
    medium = tmp_path / "M-01.json"
    critical.write_text('{"severity": "Critical", "cvss_score": "9.8"}', encoding="utf-8")
    high.write_text('{"severity": "High", "cvss_score": "7.5"}', encoding="utf-8")
    medium.write_text('{"severity": "Medium", "cvss_score": "6.9"}', encoding="utf-8")
    monkeypatch.delenv("CODE_AUDITOR_FULL_ANALYSIS", raising=False)
    monkeypatch.delenv("CODE_AUDITOR_MIN_STAGE5_CVSS", raising=False)
    monkeypatch.delenv("CODE_AUDITOR_MAX_STAGE5_VULNS", raising=False)

    selected = _select_stage5_vulnerabilities(
        [str(critical), str(high), str(medium)]
    )

    assert selected == [str(critical), str(high)]


def test_stage5_full_analysis_includes_all_severities(
    tmp_path: Path, monkeypatch
) -> None:
    critical = tmp_path / "C-01.json"
    high = tmp_path / "H-01.json"
    medium = tmp_path / "M-01.json"
    critical.write_text('{"severity": "Critical", "cvss_score": "9.8"}', encoding="utf-8")
    high.write_text('{"severity": "High", "cvss_score": "7.5"}', encoding="utf-8")
    medium.write_text('{"severity": "Medium", "cvss_score": "6.9"}', encoding="utf-8")
    monkeypatch.delenv("CODE_AUDITOR_FULL_ANALYSIS", raising=False)
    monkeypatch.delenv("CODE_AUDITOR_MIN_STAGE5_CVSS", raising=False)
    monkeypatch.delenv("CODE_AUDITOR_MAX_STAGE5_VULNS", raising=False)

    selected = _select_stage5_vulnerabilities(
        [str(critical), str(high), str(medium)], full_analysis=True
    )

    assert selected == [str(critical), str(high), str(medium)]
