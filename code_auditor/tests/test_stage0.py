from __future__ import annotations

import asyncio
import threading

from code_auditor.config import AuditConfig
from code_auditor.stages import stage0


async def test_resumed_setup_does_not_update_pinned_checkout(
    tmp_path, monkeypatch
) -> None:
    target = tmp_path / "repo"
    output = tmp_path / "results" / "audit-output-pinned"
    (target / ".git").mkdir(parents=True)
    pulls = []
    monkeypatch.setattr(stage0, "_git_pull", lambda path: pulls.append(path))

    await stage0.run_setup(
        AuditConfig(
            target=str(target),
            output_dir=str(output),
            resume=True,
            update_repo=False,
        )
    )

    assert pulls == []
    assert (output / ".markers").is_dir()
    assert (output / "stage6-disclosures").is_dir()


async def test_fresh_setup_still_updates_git_checkout(tmp_path, monkeypatch) -> None:
    target = tmp_path / "repo"
    output = tmp_path / "results" / "audit-output-new"
    (target / ".git").mkdir(parents=True)
    pulls = []
    monkeypatch.setattr(stage0, "_git_pull", lambda path: pulls.append(path))

    await stage0.run_setup(AuditConfig(target=str(target), output_dir=str(output)))

    assert pulls == [str(target)]


async def test_fresh_setup_git_pull_does_not_block_event_loop(
    tmp_path, monkeypatch
) -> None:
    target = tmp_path / "repo"
    output = tmp_path / "results" / "audit-output-new"
    (target / ".git").mkdir(parents=True)
    release = threading.Event()

    def blocking_pull(_path: str) -> None:
        assert release.wait(timeout=1), "event loop was blocked by git pull"

    monkeypatch.setattr(stage0, "_git_pull", blocking_pull)
    asyncio.get_running_loop().call_later(0.01, release.set)

    await stage0.run_setup(AuditConfig(target=str(target), output_dir=str(output)))

    assert release.is_set()
