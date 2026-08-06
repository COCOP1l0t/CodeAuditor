from __future__ import annotations

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
