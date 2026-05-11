from __future__ import annotations

import asyncio
import json
from pathlib import Path

from code_auditor import discovered
from code_auditor.checkpoint import CheckpointManager
from code_auditor.config import AuditConfig
from code_auditor.stages import stage6


def _finding(**overrides: object) -> dict[str, object]:
    finding: dict[str, object] = {
        "id": "H-01",
        "title": "Length underflow reaches memcpy",
        "location": "src/parser.c:parse_packet lines 10-24",
        "data_flow_trace": {
            "entry_point": "src/net.c:read_packet",
            "root_path": "src/parser.c",
            "sink": "memcpy(out, buf + offset, len - header_size) in src/parser.c:22",
        },
        "cwe_id": ["CWE-191"],
        "vulnerability_class": ["integer underflow"],
        "cvss_score": "8.1",
        "severity": "High",
        "trigger": "Send a packet with a length field smaller than the header size.",
        "summary": "A crafted packet length underflows before memcpy.",
        "impact": "Remote denial of service.",
    }
    finding.update(overrides)
    return finding


def _write_stage4_finding(output_dir: Path, vuln_id: str, finding: dict[str, object]) -> Path:
    path = output_dir / "stage4-vulnerabilities" / f"{vuln_id}.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(finding), encoding="utf-8")
    return path


def _write_stage5_report(output_dir: Path, vuln_id: str, title: str | None = None) -> Path:
    path = output_dir / "stage5-pocs" / vuln_id / "report.md"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        f"# {title or vuln_id}\n\n"
        "## Reproduction Status\n\n"
        "reproduced\n\n"
        "## Trigger\n\n"
        "Send a packet with a length field smaller than the header size.\n",
        encoding="utf-8",
    )
    return path


def _config(
    tmp_path: Path,
    *,
    discovered_path: Path | None = None,
) -> tuple[AuditConfig, CheckpointManager, Path, Path]:
    target = tmp_path / "target"
    output_dir = target / "audit-output"
    target.mkdir(parents=True)
    output_dir.mkdir()
    config = AuditConfig(
        target=str(target),
        output_dir=str(output_dir),
        discovered_path=str(discovered_path or target / "reproduced-bugs.md"),
        max_parallel=2,
    )
    return config, CheckpointManager(str(output_dir), resume=True), target, output_dir


def test_stage6_skips_report_when_discovered_key_already_exists(
    tmp_path: Path,
    monkeypatch,
) -> None:
    config, checkpoint, _target, output_dir = _config(tmp_path)
    finding = _finding()
    _write_stage4_finding(output_dir, "H-01", finding)
    report = _write_stage5_report(output_dir, "H-01")
    key = discovered.build_dedupe_key(finding, "")
    metadata = json.dumps({"dedupe_key": key, "title": "Known"})
    Path(config.discovered_path).write_text(
        f"# Reproduced Bugs\n\n<!-- code-auditor:discovered {metadata} -->\n",
        encoding="utf-8",
    )
    calls: list[str] = []

    async def fake_run_disclosure(report_path: str, *_args: object) -> str | None:
        calls.append(report_path)
        return report_path

    monkeypatch.setattr(stage6, "_run_disclosure", fake_run_disclosure)

    disclosure_reports = asyncio.run(stage6.run_stage6([str(report)], config, checkpoint))

    assert disclosure_reports == []
    assert calls == []


def test_stage6_skips_duplicate_keys_within_same_input_set(
    tmp_path: Path,
    monkeypatch,
) -> None:
    config, checkpoint, _target, output_dir = _config(tmp_path)
    _write_stage4_finding(output_dir, "H-01", _finding(id="H-01", title="First title"))
    _write_stage4_finding(output_dir, "H-02", _finding(id="H-02", title="Second title"))
    first_report = _write_stage5_report(output_dir, "H-01", "First report")
    second_report = _write_stage5_report(output_dir, "H-02", "Second report")
    calls: list[str] = []

    async def fake_run_disclosure(report_path: str, config: AuditConfig, *_args: object) -> str:
        calls.append(Path(report_path).parent.name)
        disclosure_report = (
            Path(config.output_dir)
            / "stage6-disclosures"
            / Path(report_path).parent.name
            / "disclosure"
            / "report.md"
        )
        disclosure_report.parent.mkdir(parents=True, exist_ok=True)
        disclosure_report.write_text("# Disclosure\n", encoding="utf-8")
        return str(disclosure_report)

    monkeypatch.setattr(stage6, "_run_disclosure", fake_run_disclosure)

    disclosure_reports = asyncio.run(
        stage6.run_stage6([str(first_report), str(second_report)], config, checkpoint)
    )

    assert len(disclosure_reports) == 1
    assert calls == ["H-01"]
    assert len(discovered.read_discovered_keys(config.discovered_path)) == 1


def test_stage6_appends_new_entry_to_configured_discovered_path(
    tmp_path: Path,
    monkeypatch,
) -> None:
    explicit_discovered = tmp_path / "custom" / "bugs.md"
    config, checkpoint, _target, output_dir = _config(tmp_path, discovered_path=explicit_discovered)
    finding_path = _write_stage4_finding(output_dir, "H-01", _finding())
    stage5_report = _write_stage5_report(output_dir, "H-01", "Length underflow reaches memcpy")

    async def fake_run_disclosure(report_path: str, config: AuditConfig, *_args: object) -> str:
        disclosure_dir = Path(config.output_dir) / "stage6-disclosures" / "H-01" / "disclosure"
        disclosure_dir.mkdir(parents=True, exist_ok=True)
        report = disclosure_dir / "report.md"
        email = disclosure_dir / "email.txt"
        zip_path = disclosure_dir / "disclosure.zip"
        report.write_text("# Disclosure\n", encoding="utf-8")
        email.write_text("Subject: Security issue\n", encoding="utf-8")
        zip_path.write_bytes(b"zip")
        return str(report)

    monkeypatch.setattr(stage6, "_run_disclosure", fake_run_disclosure)

    disclosure_reports = asyncio.run(stage6.run_stage6([str(stage5_report)], config, checkpoint))

    assert disclosure_reports == [
        str(output_dir / "stage6-disclosures" / "H-01" / "disclosure" / "report.md")
    ]
    assert explicit_discovered.exists()
    content = explicit_discovered.read_text(encoding="utf-8")
    assert discovered.read_discovered_keys(str(explicit_discovered)) == {
        discovered.build_dedupe_key(_finding(), "")
    }
    assert f"[Stage 4 Finding]({finding_path.as_posix()})" in content
    assert f"[Stage 5 Report]({stage5_report.as_posix()})" in content
    assert "Stage 6 Report" in content
    assert "email.txt" in content
    assert "disclosure.zip" in content


def test_stage6_does_not_append_when_disclosure_returns_none(
    tmp_path: Path,
    monkeypatch,
) -> None:
    config, checkpoint, _target, output_dir = _config(tmp_path)
    _write_stage4_finding(output_dir, "H-01", _finding())
    stage5_report = _write_stage5_report(output_dir, "H-01")

    async def fake_run_disclosure(*_args: object) -> None:
        return None

    monkeypatch.setattr(stage6, "_run_disclosure", fake_run_disclosure)

    disclosure_reports = asyncio.run(stage6.run_stage6([str(stage5_report)], config, checkpoint))

    assert disclosure_reports == []
    assert not Path(config.discovered_path).exists()


def test_stage6_handles_missing_stage4_finding_without_crashing(
    tmp_path: Path,
    monkeypatch,
) -> None:
    config, checkpoint, _target, output_dir = _config(tmp_path)
    stage5_report = _write_stage5_report(output_dir, "H-01", "Fallback report title")

    async def fake_run_disclosure(report_path: str, config: AuditConfig, *_args: object) -> str:
        disclosure_report = (
            Path(config.output_dir) / "stage6-disclosures" / "H-01" / "disclosure" / "report.md"
        )
        disclosure_report.parent.mkdir(parents=True, exist_ok=True)
        disclosure_report.write_text("# Disclosure\n", encoding="utf-8")
        return str(disclosure_report)

    monkeypatch.setattr(stage6, "_run_disclosure", fake_run_disclosure)

    disclosure_reports = asyncio.run(stage6.run_stage6([str(stage5_report)], config, checkpoint))

    assert disclosure_reports == [
        str(output_dir / "stage6-disclosures" / "H-01" / "disclosure" / "report.md")
    ]
    content = Path(config.discovered_path).read_text(encoding="utf-8")
    assert "## Fallback report title" in content
    assert len(discovered.read_discovered_keys(config.discovered_path)) == 1


def test_stage6_handles_non_utf8_stage4_finding_without_crashing(
    tmp_path: Path,
    monkeypatch,
) -> None:
    config, checkpoint, _target, output_dir = _config(tmp_path)
    stage5_report = _write_stage5_report(output_dir, "H-01", "Fallback report title")
    finding_path = output_dir / "stage4-vulnerabilities" / "H-01.json"
    finding_path.parent.mkdir(parents=True, exist_ok=True)
    finding_path.write_bytes(b"\xff")
    calls: list[str] = []

    async def fake_run_disclosure(report_path: str, config: AuditConfig, *_args: object) -> str:
        calls.append(report_path)
        disclosure_report = (
            Path(config.output_dir) / "stage6-disclosures" / "H-01" / "disclosure" / "report.md"
        )
        disclosure_report.parent.mkdir(parents=True, exist_ok=True)
        disclosure_report.write_text("# Disclosure\n", encoding="utf-8")
        return str(disclosure_report)

    monkeypatch.setattr(stage6, "_run_disclosure", fake_run_disclosure)

    disclosure_reports = asyncio.run(stage6.run_stage6([str(stage5_report)], config, checkpoint))

    assert calls == [str(stage5_report)]
    assert disclosure_reports == [
        str(output_dir / "stage6-disclosures" / "H-01" / "disclosure" / "report.md")
    ]
    content = Path(config.discovered_path).read_text(encoding="utf-8")
    assert "## Fallback report title" in content
    assert len(discovered.read_discovered_keys(config.discovered_path)) == 1


def test_stage6_rereads_discovered_keys_before_append(
    tmp_path: Path,
    monkeypatch,
) -> None:
    config, checkpoint, _target, output_dir = _config(tmp_path)
    finding = _finding()
    _write_stage4_finding(output_dir, "H-01", finding)
    stage5_report = _write_stage5_report(output_dir, "H-01")
    repo_snapshot = discovered.collect_repo_snapshot(config.target)

    async def fake_run_disclosure(report_path: str, config: AuditConfig, *_args: object) -> str:
        disclosure_report = (
            Path(config.output_dir) / "stage6-disclosures" / "H-01" / "disclosure" / "report.md"
        )
        disclosure_report.parent.mkdir(parents=True, exist_ok=True)
        disclosure_report.write_text("# Disclosure\n", encoding="utf-8")
        discovered.append_entries(
            config.discovered_path,
            [
                discovered.build_discovered_entry(
                    finding,
                    repo_snapshot,
                    discovered_path=config.discovered_path,
                    stage5_report_path=report_path,
                    stage6_report_path=str(disclosure_report),
                )
            ],
        )
        return str(disclosure_report)

    monkeypatch.setattr(stage6, "_run_disclosure", fake_run_disclosure)

    disclosure_reports = asyncio.run(stage6.run_stage6([str(stage5_report)], config, checkpoint))

    assert len(disclosure_reports) == 1
    content = Path(config.discovered_path).read_text(encoding="utf-8")
    assert content.count("code-auditor:discovered") == 1
