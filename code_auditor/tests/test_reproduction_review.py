from __future__ import annotations

import json
from pathlib import Path

import pytest

from code_auditor.config import AuditConfig, ValidationIssue
from code_auditor import reproduction_review


@pytest.mark.asyncio
async def test_local_reproduction_review_normalizes_disclosure_draft(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "source"
    output = tmp_path / "output"
    source.mkdir()
    finding = tmp_path / "finding.json"
    result = tmp_path / "result.json"
    retest = tmp_path / "stage5-report.md"
    finding.write_text("{}\n", encoding="utf-8")
    result.write_text("{}\n", encoding="utf-8")
    retest.write_text("# Retest\n", encoding="utf-8")

    async def fake_run_agent(*args, **kwargs) -> None:
        review_dir = output / "reproduction-review"
        assessment = {
            "schema_version": 1,
            "outcome": "reproduced",
            "disposition": "still-vulnerable",
            "summary": "The pinned revision reproduced the issue.",
            "source_analysis": "The root cause remains reachable.",
            "disclosure_update": "Record the new SHA and runtime result.",
        }
        (review_dir / "assessment.json").write_text(
            json.dumps(assessment), encoding="utf-8"
        )
        (review_dir / "retest-report.md").write_text(
            "# Latest retest\n", encoding="utf-8"
        )
        draft = review_dir / "disclosure-draft"
        draft.mkdir()
        (draft / "report.md").write_text("# Report\n", encoding="utf-8")
        (draft / "email.txt").write_text("Subject: Report\n\nBody\n", encoding="utf-8")
        (draft / "disclosure.zip").write_bytes(b"PK\x05\x06")
        reproduce = draft / "reproduce.sh"
        reproduce.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        reproduce.chmod(0o700)
        (draft / "unregistered.txt").write_text("drop me\n", encoding="utf-8")
        manifest = {
            "schema_version": 1,
            "entrypoint": "reproduce.sh",
            "files": [
                {"path": "report.md", "role": "report"},
                {"path": "email.txt", "role": "disclosure"},
                {"path": "disclosure.zip", "role": "disclosure"},
                {"path": "reproduce.sh", "role": "entrypoint"},
            ],
        }
        manifest_path = draft / "retain-manifest.json"
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        manifest_path.chmod(0o600)

    monkeypatch.setattr(reproduction_review, "run_agent", fake_run_agent)
    monkeypatch.setattr(
        reproduction_review, "validate_stage6_disclosure", lambda path: []
    )
    config = AuditConfig(
        target=str(source),
        output_dir=str(output),
        sandbox_enabled=False,
        poc_source_commit="a" * 40,
    )

    assessment = await reproduction_review.run_reproduction_review(
        config,
        candidate={
            "project": "example",
            "vuln_id": "H-01",
            "title": "Example vulnerability",
            "audited_commit": "b" * 40,
        },
        result_path=str(result),
        retest_report_path=str(retest),
        finding_path=str(finding),
        outcome="reproduced",
    )

    draft = Path(assessment["draft_path"])
    assert draft.is_dir()
    assert not (draft / "unregistered.txt").exists()
    assert {path.name for path in draft.iterdir()} == {
        "report.md",
        "email.txt",
        "disclosure.zip",
        "reproduce.sh",
        "retain-manifest.json",
    }
    assert Path(assessment["assessment_path"]).is_file()
    assert Path(assessment["retest_report_path"]).is_file()


def test_persist_draft_copies_regular_files_only(tmp_path: Path) -> None:
    source = tmp_path / "sandbox" / "disclosure-draft"
    (source / "evidence").mkdir(parents=True)
    (source / "report.md").write_text("# Report\n", encoding="utf-8")
    (source / "evidence" / "poc.py").write_text("print(1)\n", encoding="utf-8")
    destination = tmp_path / "persistent" / "disclosure-draft"

    assert reproduction_review._persist_draft(
        source, destination, max_file_bytes=4096, max_total_bytes=8192
    )
    assert (destination / "report.md").read_text(encoding="utf-8") == "# Report\n"
    assert (destination / "evidence" / "poc.py").is_file()


def test_persist_draft_rejects_symlinks_and_oversized_files(tmp_path: Path) -> None:
    source = tmp_path / "sandbox" / "disclosure-draft"
    source.mkdir(parents=True)
    (source / "report.md").write_text("# Report\n", encoding="utf-8")
    (source / "link").symlink_to(source / "report.md")
    with pytest.raises(ValueError):
        reproduction_review._persist_draft(
            source,
            tmp_path / "persist-a",
            max_file_bytes=4096,
            max_total_bytes=8192,
        )

    (source / "link").unlink()
    (source / "big.bin").write_bytes(b"x" * 64)
    with pytest.raises(ValueError):
        reproduction_review._persist_draft(
            source,
            tmp_path / "persist-b",
            max_file_bytes=16,
            max_total_bytes=8192,
        )


def test_persist_draft_preserves_owner_execute_bit(tmp_path: Path) -> None:
    # The retain manifest rejects a persisted draft whose reproduce.sh lost its
    # owner-execute bit, so the copy must carry the source mode across.
    source = tmp_path / "sandbox" / "disclosure-draft"
    source.mkdir(parents=True)
    (source / "report.md").write_text("# Report\n", encoding="utf-8")
    entrypoint = source / "reproduce.sh"
    entrypoint.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    entrypoint.chmod(0o700)
    destination = tmp_path / "persistent" / "disclosure-draft"

    reproduction_review._persist_draft(
        source, destination, max_file_bytes=4096, max_total_bytes=8192
    )
    assert (destination / "reproduce.sh").stat().st_mode & 0o100
    assert not (destination / "report.md").stat().st_mode & 0o100


@pytest.mark.asyncio
async def test_rejected_draft_stays_on_disk_with_recorded_issues(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "source"
    output = tmp_path / "output"
    source.mkdir()
    finding = tmp_path / "finding.json"
    result = tmp_path / "result.json"
    retest = tmp_path / "stage5-report.md"
    for path in (finding, result):
        path.write_text("{}\n", encoding="utf-8")
    retest.write_text("# Retest\n", encoding="utf-8")

    async def fake_run_agent(*args, **kwargs) -> None:
        review_dir = output / "reproduction-review"
        review_dir.mkdir(parents=True, exist_ok=True)
        (review_dir / "assessment.json").write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "outcome": "reproduced",
                    "disposition": "still-vulnerable",
                    "summary": "Reproduced.",
                    "source_analysis": "Unchanged.",
                    "disclosure_update": "Bump the commit.",
                }
            ),
            encoding="utf-8",
        )
        (review_dir / "retest-report.md").write_text(
            "# Latest retest\n", encoding="utf-8"
        )
        draft = review_dir / "disclosure-draft"
        draft.mkdir()
        (draft / "report.md").write_text("# Report\n", encoding="utf-8")
        (draft / "email.txt").write_text("Subject: Report\n\nBody\n", encoding="utf-8")

    monkeypatch.setattr(reproduction_review, "run_agent", fake_run_agent)
    monkeypatch.setattr(
        reproduction_review,
        "validate_stage6_disclosure",
        lambda path: [
            ValidationIssue(
                description="Missing required section in disclosure report: Summary",
                expected="Complete documents.",
                fix="Add the section.",
            )
        ],
    )
    config = AuditConfig(
        target=str(source),
        output_dir=str(output),
        sandbox_enabled=False,
        poc_source_commit="a" * 40,
    )

    with pytest.raises(ValueError, match="invalid refreshed disclosure draft"):
        await reproduction_review.run_reproduction_review(
            config,
            candidate={
                "project": "example",
                "vuln_id": "H-01",
                "title": "Example vulnerability",
                "audited_commit": "b" * 40,
            },
            result_path=str(result),
            retest_report_path=str(retest),
            finding_path=str(finding),
            outcome="reproduced",
        )

    review_dir = output / "reproduction-review"
    assert (review_dir / "disclosure-draft" / "report.md").is_file()
    recorded = json.loads(
        (review_dir / "disclosure-draft-validation.json").read_text(encoding="utf-8")
    )
    assert recorded["status"] == "rejected"
    assert recorded["issues"][0]["description"].startswith("Missing required section")
