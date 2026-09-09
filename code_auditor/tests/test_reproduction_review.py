from __future__ import annotations

import json
from pathlib import Path

import pytest

from code_auditor.config import AuditConfig
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
