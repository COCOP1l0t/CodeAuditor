from __future__ import annotations

import asyncio
import json
import shutil
from dataclasses import replace
from pathlib import Path

from code_auditor.checkpoint import CheckpointManager
from code_auditor.config import AuditConfig
from code_auditor.poc_artifacts import load_asan_report
from code_auditor.stages import stage5
from code_auditor.validation.stage5 import validate_stage5_trigger_graph


def _stage5_config(tmp_path: Path) -> tuple[AuditConfig, CheckpointManager, Path]:
    target = tmp_path / "target"
    output_dir = target / "audit-output"
    target.mkdir(parents=True)
    output_dir.mkdir()
    config = AuditConfig(
        target=str(target),
        output_dir=str(output_dir),
        max_parallel=2,
        sandbox_enabled=False,
    )
    return config, CheckpointManager(str(output_dir), resume=True), output_dir


def _write_vuln_file(output_dir: Path, vuln_id: str) -> Path:
    path = output_dir / "stage4-vulnerabilities" / f"{vuln_id}.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"id": vuln_id}), encoding="utf-8")
    return path


def _trigger_graph(finding_id: str) -> dict:
    return {
        "schema_version": 1,
        "finding_id": finding_id,
        "title": "Verified parser overflow",
        "trigger": "A crafted packet reaches the parser",
        "evidence_basis": "ASan run and debugger backtrace from the real target",
        "nodes": [
            {
                "id": "source",
                "function": "handle_packet",
                "location": "src/net.c:40",
                "role": "source",
                "description": "Receives the attacker-controlled packet",
                "evidence": "Breakpoint observed the crafted length",
                "key_parameters": [
                    {
                        "name": "length",
                        "value": "65535",
                        "origin": "packet header",
                        "security_role": "attacker-controlled length",
                        "description": "Propagates without a range check",
                    }
                ],
            },
            {
                "id": "sink",
                "function": "copy_payload",
                "location": "src/parser.c:91",
                "role": "sink",
                "description": "Copies beyond the destination buffer",
                "evidence": "ASan faulting frame",
                "key_parameters": [],
            },
        ],
        "edges": [
            {
                "from": "source",
                "to": "sink",
                "label": "calls with packet length",
                "condition": "length exceeds the destination capacity",
                "attacker_controlled": True,
            }
        ],
    }


def test_validate_stage5_trigger_graph_requires_evidence_path(tmp_path: Path) -> None:
    poc_dir = tmp_path / "H-01"
    poc_dir.mkdir()
    assert validate_stage5_trigger_graph(str(poc_dir), "H-01")

    (poc_dir / "trigger-graph.json").write_text(
        json.dumps(_trigger_graph("H-01")), encoding="utf-8"
    )
    assert validate_stage5_trigger_graph(str(poc_dir), "H-01") == []

    graph = _trigger_graph("H-01")
    graph["edges"] = []
    (poc_dir / "trigger-graph.json").write_text(
        json.dumps(graph), encoding="utf-8"
    )
    issues = validate_stage5_trigger_graph(str(poc_dir), "H-01")
    assert any("path from a trigger/source to a sink" in issue.description for issue in issues)


def test_load_asan_report_requires_complete_runtime_evidence(tmp_path: Path) -> None:
    report = tmp_path / "asan-report.txt"
    report.write_text("AddressSanitizer was enabled\n", encoding="utf-8")
    assert load_asan_report(str(report))[0] is None

    report.write_text(
        "==1==ERROR: AddressSanitizer: heap-buffer-overflow\n"
        "    #0 0x1 in copy_payload src/parser.c:91\n"
        "SUMMARY: AddressSanitizer: heap-buffer-overflow src/parser.c:91\n",
        encoding="utf-8",
    )
    loaded, errors = load_asan_report(str(report))
    assert loaded is not None
    assert errors == []


def test_run_stage5_records_standardized_graph_and_asan_names(
    tmp_path: Path, monkeypatch
) -> None:
    config, checkpoint, output_dir = _stage5_config(tmp_path)
    vuln = _write_vuln_file(output_dir, "H-05")
    poc_dir = output_dir / "stage5-pocs" / "H-05"
    calls = 0

    async def fake_run_agent(prompt: str, *_args: object, **_kwargs: object) -> str:
        nonlocal calls
        calls += 1
        assert "trigger-graph.json" in prompt
        assert "asan-report.txt" in prompt
        (poc_dir / "report.md").write_text(
            "# H-05\n\n## Reproduction Status\n\nreproduced\n",
            encoding="utf-8",
        )
        (poc_dir / "trigger-graph.json").write_text(
            json.dumps(_trigger_graph("H-05")), encoding="utf-8"
        )
        (poc_dir / "asan-report.txt").write_text(
            "==1==ERROR: AddressSanitizer: heap-buffer-overflow\n"
            "    #0 0x1 in copy_payload src/parser.c:91\n"
            "SUMMARY: AddressSanitizer: heap-buffer-overflow src/parser.c:91\n",
            encoding="utf-8",
        )
        return "done"

    monkeypatch.setattr(stage5, "run_agent", fake_run_agent)

    reports = asyncio.run(stage5.run_stage5([str(vuln)], config, checkpoint))

    assert reports == [str(poc_dir / "report.md")]
    assert calls == 1
    assert (poc_dir / "trigger-graph.json").is_file()
    assert (poc_dir / "asan-report.txt").is_file()
    assert checkpoint.is_complete("stage5:H-05")


def test_run_stage5_excludes_false_positive_reports(tmp_path: Path, monkeypatch) -> None:
    """False-positive Stage 5 reports must not be counted as reproduced."""
    config, checkpoint, output_dir = _stage5_config(tmp_path)

    vuln1 = _write_vuln_file(output_dir, "H-01")
    vuln2 = _write_vuln_file(output_dir, "H-02")

    # Pre-create a reproduced report and a false-positive report
    reproduced_dir = output_dir / "stage5-pocs" / "H-01"
    reproduced_dir.mkdir(parents=True)
    (reproduced_dir / "report.md").write_text(
        "# H-01\n\n## Reproduction Status\n\nreproduced\n", encoding="utf-8"
    )

    fp_dir = output_dir / "stage5-pocs" / "H-02_fp"
    fp_dir.mkdir(parents=True)
    (fp_dir / "report.md").write_text(
        "# H-02\n\n## Reproduction Status\n\nfalse-positive\n", encoding="utf-8"
    )

    async def fake_run_agent(*_args: object, **_kwargs: object) -> str:
        return "done"

    monkeypatch.setattr(stage5, "run_agent", fake_run_agent)

    reports = asyncio.run(stage5.run_stage5([str(vuln1), str(vuln2)], config, checkpoint))

    assert len(reports) == 1
    assert reports[0] == str(reproduced_dir / "report.md")


def test_run_stage5_excludes_failed_status_in_normal_dir(tmp_path: Path, monkeypatch) -> None:
    """A report with 'not-reproduced' status in the normal dir must be normalised to _fp and excluded."""
    config, checkpoint, output_dir = _stage5_config(tmp_path)

    vuln = _write_vuln_file(output_dir, "H-03")

    # Create a report in the normal dir but with failed status
    normal_dir = output_dir / "stage5-pocs" / "H-03"
    normal_dir.mkdir(parents=True)
    (normal_dir / "report.md").write_text(
        "# H-03\n\n## Reproduction Status\n\nnot-reproduced\n", encoding="utf-8"
    )

    async def fake_run_agent(*_args: object, **_kwargs: object) -> str:
        return "done"

    monkeypatch.setattr(stage5, "run_agent", fake_run_agent)

    reports = asyncio.run(stage5.run_stage5([str(vuln)], config, checkpoint))

    # The normal dir should have been moved to _fp and excluded from results
    assert len(reports) == 0
    assert not normal_dir.exists()
    fp_dir = output_dir / "stage5-pocs" / "H-03_fp"
    assert fp_dir.exists()
    assert (fp_dir / "report.md").exists()


def test_run_stage5_treats_partially_reproduced_as_failed(
    tmp_path: Path, monkeypatch
) -> None:
    config, checkpoint, output_dir = _stage5_config(tmp_path)
    vuln = _write_vuln_file(output_dir, "M-04")
    normal_dir = output_dir / "stage5-pocs" / "M-04"
    normal_dir.mkdir(parents=True)
    (normal_dir / "report.md").write_text(
        "# M-04\n\n## Reproduction Status\n\npartially-reproduced\n",
        encoding="utf-8",
    )

    async def fake_run_agent(*_args: object, **_kwargs: object) -> str:
        return "done"

    monkeypatch.setattr(stage5, "run_agent", fake_run_agent)

    reports = asyncio.run(stage5.run_stage5([str(vuln)], config, checkpoint))

    assert reports == []
    assert not normal_dir.exists()
    assert (output_dir / "stage5-pocs" / "M-04_fp" / "report.md").exists()


def test_run_stage5_skips_fp_on_resume(tmp_path: Path) -> None:
    """If checkpoint says complete but the report is a false positive, return None."""
    config, checkpoint, output_dir = _stage5_config(tmp_path)

    vuln = _write_vuln_file(output_dir, "H-04")

    fp_dir = output_dir / "stage5-pocs" / "H-04_fp"
    fp_dir.mkdir(parents=True)
    (fp_dir / "report.md").write_text(
        "# H-04\n\n## Reproduction Status\n\nfalse-positive\n", encoding="utf-8"
    )

    # Mark as complete in checkpoint
    checkpoint.mark_complete("stage5:H-04")

    report = asyncio.run(stage5._run_reproduce(str(vuln), config, checkpoint))

    assert report is None


def test_run_stage5_exports_only_retained_files_from_scratch(
    tmp_path: Path,
    monkeypatch,
) -> None:
    config, checkpoint, output_dir = _stage5_config(tmp_path)
    config.sandbox_enabled = True
    config.poc_source_commit = "a" * 40
    vuln = _write_vuln_file(output_dir, "H-09")
    scratch_root = tmp_path / "fake-scratch"
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
            self.prepared_commit = _commit
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
        poc = Path(work_config.output_dir) / "stage5-pocs" / "H-09"
        poc.mkdir(parents=True, exist_ok=True)
        (poc / "report.md").write_text(
            "# H-09\n\n## Reproduction Status\n\nreproduced\n",
            encoding="utf-8",
        )
        reproduce = poc / "reproduce.sh"
        reproduce.write_text("#!/bin/sh\nexec echo reproduced\n", encoding="utf-8")
        reproduce.chmod(0o700)
        (poc / "trigger-graph.json").write_text(
            json.dumps(_trigger_graph("H-09")), encoding="utf-8"
        )
        (poc / "large-build.bin").write_bytes(b"disposable")
        manifest_path = poc / "retain-manifest.json"
        manifest_path.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "entrypoint": "reproduce.sh",
                    "files": [
                        {"path": "reproduce.sh", "role": "entrypoint"},
                        {"path": "report.md", "role": "report"},
                        {"path": "trigger-graph.json", "role": "evidence"},
                    ],
                }
            ),
            encoding="utf-8",
        )
        manifest_path.chmod(0o600)
        return "done"

    monkeypatch.setattr(stage5, "DockerScratch", FakeScratch)
    monkeypatch.setattr(stage5, "run_agent", fake_run_agent)

    reports = asyncio.run(stage5.run_stage5([str(vuln)], config, checkpoint))

    persistent = output_dir / "stage5-pocs" / "H-09"
    assert reports == [str(persistent / "report.md")]
    assert sorted(path.name for path in persistent.iterdir()) == [
        "report.md",
        "reproduce.sh",
        "retain-manifest.json",
        "trigger-graph.json",
    ]
    assert not (persistent / "large-build.bin").exists()
    assert instances and instances[0].closed is True  # type: ignore[attr-defined]
    assert instances[0].prepared_commit == "a" * 40  # type: ignore[attr-defined]
    assert checkpoint.is_complete("stage5:H-09")


def test_run_stage5_repairs_invalid_retain_manifest_once(
    tmp_path: Path,
    monkeypatch,
) -> None:
    config, checkpoint, output_dir = _stage5_config(tmp_path)
    config.sandbox_enabled = True
    config.poc_source_commit = "b" * 40
    vuln = _write_vuln_file(output_dir, "H-10")
    scratch_root = tmp_path / "fake-scratch"

    class FakeScratch:
        def __init__(self, owner: AuditConfig, _task_name: str) -> None:
            self.owner = owner
            self.source_dir = scratch_root / "source"
            self.artifact_dir = scratch_root / "artifacts"
            self.input_dir = scratch_root / "inputs"

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

        def copy_input(self, source: str, name: str) -> Path:
            destination = self.input_dir / name
            shutil.copyfile(source, destination)
            return destination

        async def close(self) -> None:
            return None

    prompts: list[str] = []

    async def fake_run_agent(
        prompt: str,
        work_config: AuditConfig,
        **_kwargs: object,
    ) -> str:
        prompts.append(prompt)
        poc = Path(work_config.output_dir) / "stage5-pocs" / "H-10"
        poc.mkdir(parents=True, exist_ok=True)
        if len(prompts) == 1:
            (poc / "report.md").write_text(
                "# H-10\n\n## Reproduction Status\n\nreproduced\n",
                encoding="utf-8",
            )
            reproduce = poc / "reproduce.sh"
            reproduce.write_text("#!/bin/sh\nexec echo reproduced\n", encoding="utf-8")
            reproduce.chmod(0o700)
            (poc / "trigger-graph.json").write_text(
                json.dumps(_trigger_graph("H-10")), encoding="utf-8"
            )
            (poc / "retain-manifest.json").write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "entrypoint": "reproduce.sh",
                        "files": [],
                    }
                ),
                encoding="utf-8",
            )
        else:
            assert "files must be a non-empty array" in prompt
            assert "Do not alter the reproduction result" in prompt
            (poc / "retain-manifest.json").write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "entrypoint": "reproduce.sh",
                        "files": [
                            {"path": "reproduce.sh", "role": "entrypoint"},
                            {"path": "report.md", "role": "report"},
                            {"path": "trigger-graph.json", "role": "evidence"},
                        ],
                    }
                ),
                encoding="utf-8",
            )
        return "done"

    monkeypatch.setattr(stage5, "DockerScratch", FakeScratch)
    monkeypatch.setattr(stage5, "run_agent", fake_run_agent)

    reports = asyncio.run(stage5.run_stage5([str(vuln)], config, checkpoint))

    persistent = output_dir / "stage5-pocs" / "H-10"
    assert reports == [str(persistent / "report.md")]
    assert len(prompts) == 2
    assert sorted(path.name for path in persistent.iterdir()) == [
        "report.md",
        "reproduce.sh",
        "retain-manifest.json",
        "trigger-graph.json",
    ]
    assert checkpoint.is_complete("stage5:H-10")


def test_stage5_preserves_agent_error_when_scratch_cleanup_fails(
    tmp_path: Path,
    monkeypatch,
) -> None:
    config, checkpoint, output_dir = _stage5_config(tmp_path)
    config.sandbox_enabled = True
    vuln = _write_vuln_file(output_dir, "H-11")
    scratch_root = tmp_path / "fake-scratch"

    class FakeScratch:
        def __init__(self, owner: AuditConfig, _task_name: str) -> None:
            self.source_dir = scratch_root / "source"
            self.artifact_dir = scratch_root / "artifacts"
            self.input_dir = scratch_root / "inputs"

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

        def copy_input(self, source: str, name: str) -> Path:
            destination = self.input_dir / name
            shutil.copyfile(source, destination)
            return destination

        async def close(self) -> None:
            raise RuntimeError("cleanup failed")

    async def failing_agent(*_args: object, **_kwargs: object) -> str:
        raise RuntimeError("agent failed")

    monkeypatch.setattr(stage5, "DockerScratch", FakeScratch)
    monkeypatch.setattr(stage5, "capture_repo_identity", lambda _target: {"commit": ""})
    monkeypatch.setattr(stage5, "run_agent", failing_agent)

    reports = asyncio.run(stage5.run_stage5([str(vuln)], config, checkpoint))

    assert reports == []
    assert len(config.task_errors) == 1
    assert "agent failed" in config.task_errors[0]
    assert "cleanup failed" not in config.task_errors[0]
