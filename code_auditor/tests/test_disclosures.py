from __future__ import annotations

import asyncio
import json
import shutil
from dataclasses import replace
from pathlib import Path

import pytest

from code_auditor.checkpoint import CheckpointManager
from code_auditor.config import AuditConfig
from code_auditor.disclosures import build_dedupe_key, extract_email_subject
from code_auditor.stages import stage6
from code_auditor.utils import extract_json_object


def _finding(**overrides: object) -> dict[str, object]:
    finding: dict[str, object] = {
        "id": "H-01",
        "title": "Length underflow reaches memcpy",
        "location": "src/parser.c:parse_packet lines 10-24",
        "data_flow_trace": {
            "entry_point": "src/net.c:read_packet",
            "root_path": "src/parser.c",
            "sink": "memcpy(out, buf + offset, len - header_size)",
        },
        "cwe_id": ["CWE-191"],
        "vulnerability_class": ["integer underflow"],
        "trigger": "Send a packet whose length is smaller than the header.",
        "summary": "A crafted packet length underflows before memcpy.",
    }
    finding.update(overrides)
    return finding


def _write_stage4(output_dir: Path, vuln_id: str, finding: dict) -> Path:
    path = output_dir / "stage4-vulnerabilities" / f"{vuln_id}.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(finding), encoding="utf-8")
    return path


def _write_stage5(output_dir: Path, vuln_id: str) -> Path:
    path = output_dir / "stage5-pocs" / vuln_id / "report.md"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        f"# {vuln_id}\n\n"
        "## Reproduction Status\n\nreproduced\n\n"
        "## Trigger\n\nSend a crafted packet.\n",
        encoding="utf-8",
    )
    return path


def _stage6_config(
    tmp_path: Path,
    *,
    known_disclosures: tuple[dict, ...] = (),
) -> tuple[AuditConfig, CheckpointManager, Path, Path]:
    target = tmp_path / "target"
    output_dir = target / "audit-output"
    target.mkdir(parents=True)
    output_dir.mkdir()
    config = AuditConfig(
        target=str(target),
        output_dir=str(output_dir),
        max_parallel=2,
        known_disclosures=known_disclosures,
    )
    return config, CheckpointManager(str(output_dir), resume=True), target, output_dir


def test_build_dedupe_key_ignores_run_local_fields() -> None:
    first = _finding(id="H-01", audited_commit="one")
    second = _finding(id="M-99", audited_commit="two")

    assert build_dedupe_key(first, "https://example.test/repo.git") == (
        build_dedupe_key(second, "https://example.test/repo.git")
    )


def test_build_dedupe_key_changes_with_stable_sink() -> None:
    changed = _finding(
        data_flow_trace={
            "entry_point": "src/net.c:read_packet",
            "root_path": "src/parser.c",
            "sink": "memmove(dst, src, len)",
        }
    )

    assert build_dedupe_key(_finding(), "") != build_dedupe_key(changed, "")


def test_stage6_skips_database_known_disclosure(tmp_path: Path, monkeypatch) -> None:
    finding = _finding()
    key = build_dedupe_key(finding, "")
    config, checkpoint, _target, output_dir = _stage6_config(
        tmp_path,
        known_disclosures=({"dedupe_key": key, "title": "Known"},),
    )
    _write_stage4(output_dir, "H-01", finding)
    report = _write_stage5(output_dir, "H-01")
    calls: list[str] = []

    async def fake_run_disclosure(report_path: str, *_args: object) -> str:
        calls.append(report_path)
        return report_path

    monkeypatch.setattr(stage6, "_run_disclosure", fake_run_disclosure)

    result = asyncio.run(stage6.run_stage6([str(report)], config, checkpoint))

    assert result == []
    assert calls == []


def test_stage6_deduplicates_current_input_and_only_writes_artifacts(
    tmp_path: Path, monkeypatch
) -> None:
    config, checkpoint, target, output_dir = _stage6_config(tmp_path)
    _write_stage4(output_dir, "H-01", _finding(id="H-01", title="First"))
    _write_stage4(output_dir, "H-02", _finding(id="H-02", title="Second"))
    first = _write_stage5(output_dir, "H-01")
    second = _write_stage5(output_dir, "H-02")
    calls: list[str] = []

    async def fake_run_disclosure(
        report_path: str, config: AuditConfig, *_args: object
    ) -> str:
        vuln_id = Path(report_path).parent.name
        calls.append(vuln_id)
        report = (
            Path(config.output_dir)
            / "stage6-disclosures"
            / vuln_id
            / "disclosure"
            / "report.md"
        )
        report.parent.mkdir(parents=True)
        report.write_text("# Disclosure\n", encoding="utf-8")
        return str(report)

    monkeypatch.setattr(stage6, "_run_disclosure", fake_run_disclosure)

    result = asyncio.run(
        stage6.run_stage6([str(first), str(second)], config, checkpoint)
    )

    assert len(result) == 1
    assert calls == ["H-01"]
    assert not hasattr(config, "discovered_path")
    assert list(target.rglob("*.html")) == []


def test_stage6_handles_missing_stage4_with_report_fallback(
    tmp_path: Path, monkeypatch
) -> None:
    config, checkpoint, _target, output_dir = _stage6_config(tmp_path)
    report = _write_stage5(output_dir, "H-01")

    async def fake_run_disclosure(
        report_path: str, config: AuditConfig, *_args: object
    ) -> str:
        result = (
            Path(config.output_dir)
            / "stage6-disclosures"
            / Path(report_path).parent.name
            / "disclosure"
            / "report.md"
        )
        result.parent.mkdir(parents=True)
        result.write_text("# Disclosure\n", encoding="utf-8")
        return str(result)

    monkeypatch.setattr(stage6, "_run_disclosure", fake_run_disclosure)

    result = asyncio.run(stage6.run_stage6([str(report)], config, checkpoint))

    assert len(result) == 1


def test_run_disclosure_exports_only_retained_files_from_scratch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, checkpoint, _target, output_dir = _stage6_config(tmp_path)
    report = _write_stage5(output_dir, "H-07")
    scratch_root = tmp_path / "fake-stage6-scratch"
    instances: list[object] = []

    class FakeScratch:
        def __init__(self, owner: AuditConfig, _task_name: str) -> None:
            self.owner = owner
            self.source_dir = scratch_root / "source"
            self.artifact_dir = scratch_root / "artifacts"
            self.input_dir = scratch_root / "inputs"
            self.closed = False
            instances.append(self)

        async def prepare(self, _target: str, _commit: str):  # type: ignore[no-untyped-def]
            self.source_dir.mkdir(parents=True)
            self.artifact_dir.mkdir(parents=True)
            self.input_dir.mkdir(parents=True)
            return self

        def audit_config(self, owner: AuditConfig) -> AuditConfig:
            return replace(
                owner,
                target=str(self.source_dir),
                output_dir=str(self.artifact_dir),
                poc_worktree=str(self.source_dir),
            )

        def copy_input_tree(self, source: str, name: str) -> Path:
            destination = self.input_dir / name
            shutil.copytree(source, destination)
            return destination

        def copy_input(self, source: str, name: str) -> Path:
            destination = self.input_dir / name
            shutil.copyfile(source, destination)
            return destination

        async def close(self) -> None:
            self.closed = True

    async def fake_run_agent(
        _prompt: str,
        work_config: AuditConfig,
        **_kwargs: object,
    ) -> str:
        disclosure = (
            Path(work_config.output_dir)
            / "stage6-disclosures"
            / "H-07"
            / "disclosure"
        )
        disclosure.mkdir(parents=True, exist_ok=True)
        reproduce = disclosure / "reproduce.sh"
        reproduce.write_text("#!/bin/sh\nexec echo reproduced\n", encoding="utf-8")
        reproduce.chmod(0o700)
        (disclosure / "report.md").write_text("# Disclosure\n", encoding="utf-8")
        (disclosure / "email.txt").write_text("Subject: H-07\n", encoding="utf-8")
        (disclosure / "disclosure.zip").write_bytes(b"PK\x05\x06" + b"\0" * 18)
        (disclosure / "temporary-build.bin").write_bytes(b"disposable")
        manifest_path = disclosure / "retain-manifest.json"
        manifest_path.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "entrypoint": "reproduce.sh",
                    "files": [
                        {"path": "reproduce.sh", "role": "entrypoint"},
                        {"path": "report.md", "role": "report"},
                        {"path": "email.txt", "role": "disclosure"},
                        {"path": "disclosure.zip", "role": "disclosure"},
                    ],
                }
            ),
            encoding="utf-8",
        )
        manifest_path.chmod(0o600)
        return "done"

    monkeypatch.setattr(stage6, "DockerScratch", FakeScratch)
    monkeypatch.setattr(stage6, "run_agent", fake_run_agent)

    result = asyncio.run(stage6._run_disclosure(str(report), config, checkpoint))

    persistent = output_dir / "stage6-disclosures" / "H-07" / "disclosure"
    assert result == str(persistent / "report.md")
    assert sorted(path.name for path in persistent.iterdir()) == [
        "disclosure.zip",
        "email.txt",
        "report.md",
        "reproduce.sh",
        "retain-manifest.json",
    ]
    assert not (persistent / "temporary-build.bin").exists()
    assert instances and instances[0].closed is True  # type: ignore[attr-defined]
    assert checkpoint.is_complete("stage6:H-07")


def test_semantic_dedupe_uses_database_metadata(tmp_path: Path, monkeypatch) -> None:
    config, _checkpoint, _target, output_dir = _stage6_config(tmp_path)
    finding = _finding()
    finding_path = _write_stage4(output_dir, "H-01", finding)
    report = _write_stage5(output_dir, "H-01")
    candidate = stage6._load_candidate(str(report), config, "")
    assert candidate.finding_path == str(finding_path)
    prompts: list[str] = []

    async def fake_run_agent(prompt: str, *_args: object, **_kwargs: object) -> str:
        prompts.append(prompt)
        return json.dumps(
            {
                "decision": "duplicate",
                "matched_dedupe_key": "sha256:" + "a" * 64,
                "reason": "same sink and trigger",
            }
        )

    monkeypatch.setattr(stage6, "run_agent", fake_run_agent)
    existing = (
        {
            "dedupe_key": "sha256:" + "a" * 64,
            "title": "Existing database row",
            "location": finding["location"],
            "cwe": "CWE-191",
            "vulnerability_class": "integer underflow",
            "trigger": finding["trigger"],
            "summary": finding["summary"],
        },
    )

    result = asyncio.run(
        stage6._filter_semantic_duplicates([candidate], existing, config)
    )

    assert result == []
    assert "Existing database row" in prompts[0]


@pytest.mark.parametrize(
    ("content", "expected"),
    [
        ("Subject: Buffer overflow in parser\n\nBody\n", "Buffer overflow in parser"),
        ("subject: Lowercase subject\n", "Lowercase subject"),
        ("Subject: Folded\n continuation\n\nBody\n", "Folded continuation"),
    ],
)
def test_extract_email_subject(tmp_path: Path, content: str, expected: str) -> None:
    email = tmp_path / "email.txt"
    email.write_text(content, encoding="utf-8")

    assert extract_email_subject(str(email)) == expected


def test_extract_email_subject_handles_missing_or_absent_subject(tmp_path: Path) -> None:
    email = tmp_path / "email.txt"
    email.write_text("To: security@example.test\n\nBody\n", encoding="utf-8")

    assert extract_email_subject(str(email)) is None
    assert extract_email_subject(str(tmp_path / "missing.txt")) is None


@pytest.mark.parametrize(
    ("text", "decision"),
    [
        ('{"decision": "duplicate"}', "duplicate"),
        ('prefix{"decision": "duplicate"}suffix', "duplicate"),
        ('```json\n{"decision": "new"}\n```', "new"),
    ],
)
def test_extract_json_object(text: str, decision: str) -> None:
    result = extract_json_object(text)

    assert result is not None
    assert json.loads(result)["decision"] == decision


def test_extract_json_object_rejects_invalid_text() -> None:
    assert extract_json_object("no json here") is None
