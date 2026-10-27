import json
from pathlib import Path

import pytest

from code_auditor.poc_backfill import (
    BackfillCandidate,
    _build_config,
    _is_nonfatal_cleanup_error,
    _provider_is_unavailable,
    _recovery_output,
    _run_group,
)
from code_auditor.web.settings import WebSettings


def _candidate(tmp_path: Path) -> BackfillCandidate:
    return BackfillCandidate(
        project="qemu",
        dedupe_key="sha256:" + "a" * 64,
        title="Historical finding",
        review_status="unreviewed",
        previous_poc_status="",
        vuln_id="H-01",
        finding_path=str(tmp_path / "H-01.json"),
        target=str(tmp_path / "repo"),
        source_output_dir=str(tmp_path / "old-output"),
        commit="b" * 40,
        repo_url="https://example.test/qemu.git",
    )


def test_build_config_can_override_active_web_backend(tmp_path: Path) -> None:
    settings = WebSettings.for_state_dir(str(tmp_path), backend="claude", sandbox_runtime="runsc")

    config = _build_config(
        settings,
        _candidate(tmp_path),
        str(tmp_path / "recovery"),
        backend="codex",
        model="gpt-5.6-luna",
    )

    assert settings.backend == "claude"
    assert config.backend == "codex"
    assert config.model == "gpt-5.6-luna"
    assert config.provider_mode == settings.codex_provider.mode
    assert config.sandbox_runtime == "runsc"


@pytest.mark.parametrize(
    "message",
    [
        "Failed to authenticate. API Error: 403",
        "You've reached your weekly (7-day) usage limit.",
        "insufficient_quota",
        "Quota exceeded for this account",
    ],
)
def test_provider_unavailable_errors_stop_the_batch(message: str) -> None:
    assert _provider_is_unavailable(RuntimeError(message)) is True


def test_candidate_error_does_not_stop_the_batch() -> None:
    assert _provider_is_unavailable(RuntimeError("build failed")) is False


def test_cleanup_race_is_nonfatal_after_report_export() -> None:
    assert _is_nonfatal_cleanup_error(
        RuntimeError(
            "cannot remove sandbox container(s) abc: removal of container abc "
            "is already in progress"
        )
    ) is True
    assert _is_nonfatal_cleanup_error(RuntimeError("build failed")) is False
    assert _is_nonfatal_cleanup_error(RuntimeError(
        "sandbox container cleanup could not be verified: removal already in progress"
    )) is False


def test_recovery_output_isolated_when_commit_tree_already_exists(tmp_path: Path) -> None:
    settings = WebSettings.for_state_dir(str(tmp_path), backend="codex")
    candidate = _candidate(tmp_path)
    base = Path(_recovery_output(settings, candidate))
    base.mkdir(parents=True)

    retry = Path(_recovery_output(settings, candidate))
    assert retry == base.with_name(f"{base.name}-retry-2")


async def test_backfill_group_writes_run_level_trajectory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = WebSettings.for_state_dir(str(tmp_path), backend="codex")
    candidate = _candidate(tmp_path)
    finding = Path(candidate.finding_path)
    finding.write_text(
        json.dumps(
            {
                "id": "H-01",
                "title": "Historical finding",
                "location": "src/a.c:1",
                "trigger": "crafted input",
                "data_flow_trace": {"entry_point": "main", "sink": "memcpy"},
                "cwe_id": ["CWE-120"],
                "vulnerability_class": ["buffer-overflow"],
                "cvss_score": "8.1",
                "severity": "High",
            }
        ),
        encoding="utf-8",
    )

    class FakeStore:
        def create_run(self, *_args, **_kwargs):
            return 7

        def persist_artifacts(self, *_args, **_kwargs):
            return None

        def finish_run(self, *_args, **_kwargs):
            return None

    async def fake_reproduce(*_args, **_kwargs):
        return None

    monkeypatch.setattr("code_auditor.poc_backfill._pin_run_identity", lambda *_: None)
    monkeypatch.setattr("code_auditor.poc_backfill._run_reproduce", fake_reproduce)

    results = await _run_group(FakeStore(), settings, [candidate])

    assert results[0]["result"] == "not-reproduced"
    output_dir = Path(results[0]["recovery_output_dir"])
    trajectory_path = output_dir / "trajectories" / "trajectory.json"
    assert trajectory_path.is_file()
    trajectory = json.loads(trajectory_path.read_text(encoding="utf-8"))
    assert trajectory["extra"]["run_kind"] == "poc_backfill"
