from __future__ import annotations

import asyncio
import json
from pathlib import Path

from code_auditor.checkpoint import CheckpointManager
from code_auditor.config import AuditConfig
from code_auditor.discovered import (
    append_entries,
    build_dedupe_key,
    build_discovered_entry,
    collect_repo_snapshot,
    read_discovered_keys,
)
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


def _stage6_config(
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
        discovered_path=str(discovered_path or target / "reproduced-bugs.html"),
        max_parallel=2,
    )
    return config, CheckpointManager(str(output_dir), resume=True), target, output_dir


def test_read_discovered_keys_returns_empty_set_for_missing_file(tmp_path: Path) -> None:
    assert read_discovered_keys(str(tmp_path / "missing.html")) == set()


def test_read_discovered_keys_parses_entries_and_ignores_malformed_json(tmp_path: Path) -> None:
    path = tmp_path / "bugs.html"
    path.write_text(
        "# Reproduced Bugs\n\n"
        "<!-- code-auditor:discovered {\"dedupe_key\": \"sha256:abc\", \"title\": \"One\"} -->\n\n"
        "<!-- code-auditor:discovered {not json} -->\n\n"
        "<!-- code-auditor:discovered {\"dedupe_key\": \"sha256:def\", \"title\": \"Two\"} -->\n",
        encoding="utf-8",
    )

    assert read_discovered_keys(str(path)) == {"sha256:abc", "sha256:def"}


def test_build_dedupe_key_ignores_run_local_id_and_audited_commit() -> None:
    base = _finding(audited_commit="abc123")
    changed_run_fields = _finding(id="H-99", audited_commit="def456")

    assert build_dedupe_key(base, "https://example.test/repo.git") == build_dedupe_key(
        changed_run_fields,
        "https://example.test/repo.git",
    )


def test_build_dedupe_key_changes_when_stable_sink_changes() -> None:
    base = _finding()
    changed_sink = _finding(
        data_flow_trace={
            "entry_point": "src/net.c:read_packet",
            "root_path": "src/parser.c",
            "sink": "memmove(out, buf, len) in src/parser.c:45",
        },
    )

    assert build_dedupe_key(base, "https://example.test/repo.git") != build_dedupe_key(
        changed_sink,
        "https://example.test/repo.git",
    )


def test_append_entries_creates_parent_header_and_clean_spacing(tmp_path: Path) -> None:
    path = tmp_path / "nested" / "bugs.html"

    append_entries(
        str(path),
        [
            '<details class="reproduced-bug"><summary><span class="bug-title">Bug One</span></summary><p>Details</p></details>',
        ],
    )
    append_entries(
        str(path),
        [
            '<details class="reproduced-bug"><summary><span class="bug-title">Bug Two</span></summary><p>More details</p></details>',
        ],
    )

    content = path.read_text(encoding="utf-8")
    assert content.startswith("<!doctype html>\n<html lang=\"en\">\n")
    assert "<main>\n<h1>Reproduced Bugs</h1>" in content
    assert content.count("</main>") == 1
    assert content.count("</html>") == 1
    assert "<p>Details</p></details>\n\n<details class=\"reproduced-bug\"><summary>" in content
    assert content.index("<span class=\"bug-title\">Bug Two</span>") < content.index("</main>")
    assert content.endswith("</main>\n</body>\n</html>\n")


def test_append_entries_includes_status_json_load_and_export_controls(tmp_path: Path) -> None:
    path = tmp_path / "reproduced-bugs.html"

    append_entries(
        str(path),
        [
            '<details class="reproduced-bug" data-dedupe-key="sha256:abc" data-review-status="unreviewed">'
            '<summary><span class="bug-title">Bug One</span></summary></details>',
        ],
    )

    content = path.read_text(encoding="utf-8")
    assert 'class="load-status-json"' in content
    assert 'Load status JSON' in content
    assert 'class="export-status-json"' in content
    assert 'Export status JSON' in content
    assert 'class="status-json-input"' in content
    assert 'accept="application/json,.json"' in content
    assert "function currentStatusMap()" in content
    assert "function exportStatusJson()" in content
    assert "function downloadStatusJson(text)" in content
    assert "window.showSaveFilePicker" in content
    assert "suggestedName: statusJsonFileName" in content
    assert "const writable = await handle.createWritable()" in content
    assert "await writable.write(text)" in content
    assert "function loadSelectedStatusJson(file)" in content
    assert 'download = statusJsonFileName' in content


def test_read_discovered_keys_handles_comment_terminator_in_metadata_title(tmp_path: Path) -> None:
    path = tmp_path / "reproduced-bugs.html"
    finding = _finding(title="A --> B")
    repo_snapshot = {
        "target_path": str(tmp_path),
        "repo_url": "https://example.test/repo.git",
        "audited_commit": "abcdef123456",
        "version": "",
        "description": "",
        "dirty_status": "clean",
        "audit_finished_date": "2026-05-11",
    }
    entry = build_discovered_entry(finding, repo_snapshot)

    append_entries(str(path), [entry])

    assert read_discovered_keys(str(path)) == {build_dedupe_key(finding, repo_snapshot["repo_url"])}


def test_build_discovered_entry_uses_absolute_link_for_sibling_artifact_path(tmp_path: Path) -> None:
    discovered_path = tmp_path / "target" / "reproduced-bugs.html"
    sibling_stage5 = tmp_path / "target-sibling" / "stage5" / "report.md"

    entry = build_discovered_entry(
        _finding(),
        {
            "target_path": str(tmp_path / "target"),
            "repo_url": "",
            "audited_commit": "",
            "version": "",
            "description": "",
            "dirty_status": "unknown",
            "audit_finished_date": "2026-05-11",
        },
        discovered_path=str(discovered_path),
        stage5_report_path=str(sibling_stage5),
    )

    assert f'<a href="{sibling_stage5.as_posix()}">Stage 5 Report</a>' in entry
    assert "../target-sibling/stage5/report.md" not in entry


def test_build_discovered_entry_includes_visible_fields_and_relative_links_as_html(tmp_path: Path) -> None:
    discovered_path = tmp_path / "target" / "reproduced-bugs.html"
    output_dir = tmp_path / "target" / "audit-output"
    stage4 = output_dir / "stage4-vulnerabilities" / "H-01.json"
    stage5 = output_dir / "stage5-pocs" / "H-01" / "report.md"
    stage6_report = output_dir / "stage6-disclosures" / "H-01" / "disclosure" / "report.md"
    stage6_email = output_dir / "stage6-disclosures" / "H-01" / "disclosure" / "email.md"
    stage6_zip = output_dir / "stage6-disclosures" / "H-01" / "disclosure" / "poc.zip"

    entry = build_discovered_entry(
        _finding(),
        {
            "target_path": str(tmp_path / "target"),
            "repo_url": "https://example.test/repo.git",
            "audited_commit": "abcdef123456",
            "version": "1.2.3",
            "description": "Example package",
            "dirty_status": "clean",
            "audit_finished_date": "2026-05-11",
        },
        discovered_path=str(discovered_path),
        stage4_finding_path=str(stage4),
        stage5_report_path=str(stage5),
        stage6_report_path=str(stage6_report),
        stage6_email_path=str(stage6_email),
        stage6_zip_path=str(stage6_zip),
    )

    assert '<details class="reproduced-bug" data-dedupe-key="sha256:' in entry
    assert 'data-review-status="unreviewed">' in entry
    assert '<summary><span class="bug-title">Length underflow reaches memcpy</span>' in entry
    assert '<span class="review-tag review-tag-unreviewed">unreviewed</span></summary>' in entry
    assert '<fieldset class="review-status" data-review-status="unreviewed">' in entry
    assert '<legend>Review status</legend>' in entry
    assert '<input type="radio" name="review-status-' in entry
    assert 'value="unreviewed" checked>' in entry
    assert 'value="reported">' in entry
    assert 'value="confirmed">' in entry
    assert 'value="rejected">' in entry
    assert 'value="duplicated">' in entry
    assert "disabled" not in entry
    assert "<dt>Repository</dt><dd>https://example.test/repo.git</dd>" in entry
    assert "<dt>Version</dt><dd>1.2.3</dd>" in entry
    assert "<dt>Audited Commit</dt><dd><code>abcdef123456</code></dd>" in entry
    assert "<dt>Audit Finished</dt><dd>2026-05-11</dd>" in entry
    assert "<dt>Severity</dt><dd>High / CVSS 8.1</dd>" in entry
    assert "<dt>CWE</dt><dd>CWE-191</dd>" in entry
    assert "<dt>Location</dt><dd><code>src/parser.c:parse_packet lines 10-24</code></dd>" in entry
    assert "<h3>Summary</h3>" in entry
    assert "Remote denial of service." in entry
    assert '<a href="audit-output/stage4-vulnerabilities/H-01.json">Stage 4 Finding</a>' in entry
    assert '<a href="audit-output/stage5-pocs/H-01/report.md">Stage 5 Report</a>' in entry
    assert '<a href="audit-output/stage6-disclosures/H-01/disclosure/report.md">Stage 6 Report</a>' in entry
    assert '<a href="audit-output/stage6-disclosures/H-01/disclosure/email.md">Stage 6 Email</a>' in entry
    assert '<a href="audit-output/stage6-disclosures/H-01/disclosure/poc.zip">Stage 6 Zip</a>' in entry

    metadata_line = next(line for line in entry.splitlines() if line.startswith("<!-- code-auditor:discovered "))
    payload = metadata_line.removeprefix("<!-- code-auditor:discovered ").removesuffix(" -->")
    metadata = json.loads(payload)
    assert metadata["dedupe_key"].startswith("sha256:")
    assert metadata["title"] == "Length underflow reaches memcpy"
    assert metadata["repo_url"] == "https://example.test/repo.git"
    assert metadata["audited_commit"] == "abcdef123456"
    assert metadata["audit_finished_date"] == "2026-05-11"
    assert metadata["review_status"] == "unreviewed"


def test_append_entries_writes_status_sidecar_without_overwriting_existing_statuses(tmp_path: Path) -> None:
    path = tmp_path / "reproduced-bugs.html"
    repo_snapshot = {
        "target_path": str(tmp_path),
        "repo_url": "https://example.test/repo.git",
        "audited_commit": "abcdef123456",
        "version": "",
        "description": "",
        "dirty_status": "clean",
        "audit_finished_date": "2026-05-11",
    }
    first_finding = _finding(review_status="confirmed")
    second_finding = _finding(
        title="Different sink",
        data_flow_trace={
            "entry_point": "src/net.c:read_packet",
            "root_path": "src/parser.c",
            "sink": "memmove(out, buf, len) in src/parser.c:45",
        },
    )
    first_key = build_dedupe_key(first_finding, repo_snapshot["repo_url"])
    second_key = build_dedupe_key(second_finding, repo_snapshot["repo_url"])

    append_entries(str(path), [build_discovered_entry(first_finding, repo_snapshot)])
    sidecar = tmp_path / "reproduced-bugs-status.json"
    assert json.loads(sidecar.read_text(encoding="utf-8")) == {first_key: "confirmed"}

    sidecar.write_text(json.dumps({first_key: "rejected"}, indent=2) + "\n", encoding="utf-8")
    append_entries(str(path), [build_discovered_entry(second_finding, repo_snapshot)])

    assert json.loads(sidecar.read_text(encoding="utf-8")) == {
        first_key: "rejected",
        second_key: "unreviewed",
    }


def test_stage6_skips_report_when_discovered_key_already_exists(
    tmp_path: Path,
    monkeypatch,
) -> None:
    config, checkpoint, _target, output_dir = _stage6_config(tmp_path)
    finding = _finding()
    _write_stage4_finding(output_dir, "H-01", finding)
    report = _write_stage5_report(output_dir, "H-01")
    key = build_dedupe_key(finding, "")
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
    config, checkpoint, _target, output_dir = _stage6_config(tmp_path)
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
    assert len(read_discovered_keys(config.discovered_path)) == 1


def test_stage6_appends_new_entry_to_configured_discovered_path(
    tmp_path: Path,
    monkeypatch,
) -> None:
    explicit_discovered = tmp_path / "custom" / "bugs.html"
    config, checkpoint, _target, output_dir = _stage6_config(
        tmp_path,
        discovered_path=explicit_discovered,
    )
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
    assert read_discovered_keys(str(explicit_discovered)) == {
        build_dedupe_key(_finding(), "")
    }
    assert f'<a href="{finding_path.as_posix()}">Stage 4 Finding</a>' in content
    assert f'<a href="{stage5_report.as_posix()}">Stage 5 Report</a>' in content
    assert "Stage 6 Report" in content
    assert "email.txt" in content
    assert "disclosure.zip" in content


def test_stage6_does_not_append_when_disclosure_returns_none(
    tmp_path: Path,
    monkeypatch,
) -> None:
    config, checkpoint, _target, output_dir = _stage6_config(tmp_path)
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
    config, checkpoint, _target, output_dir = _stage6_config(tmp_path)
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
    assert '<span class="bug-title">Fallback report title</span>' in content
    assert len(read_discovered_keys(config.discovered_path)) == 1


def test_stage6_rereads_discovered_keys_before_append(
    tmp_path: Path,
    monkeypatch,
) -> None:
    config, checkpoint, _target, output_dir = _stage6_config(tmp_path)
    finding = _finding()
    _write_stage4_finding(output_dir, "H-01", finding)
    stage5_report = _write_stage5_report(output_dir, "H-01")
    repo_snapshot = collect_repo_snapshot(config.target)

    async def fake_run_disclosure(report_path: str, config: AuditConfig, *_args: object) -> str:
        disclosure_report = (
            Path(config.output_dir) / "stage6-disclosures" / "H-01" / "disclosure" / "report.md"
        )
        disclosure_report.parent.mkdir(parents=True, exist_ok=True)
        disclosure_report.write_text("# Disclosure\n", encoding="utf-8")
        append_entries(
            config.discovered_path,
            [
                build_discovered_entry(
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
    assert content.count("<!-- code-auditor:discovered") == 1


def test_collect_repo_snapshot_handles_non_git_target_without_raising(tmp_path: Path) -> None:
    snapshot = collect_repo_snapshot(str(tmp_path), audit_finished_date="2026-05-11")

    assert snapshot["target_path"] == str(tmp_path)
    assert snapshot["repo_url"] == ""
    assert snapshot["audited_commit"] == ""
    assert snapshot["dirty_status"] == "unknown"
    assert snapshot["audit_finished_date"] == "2026-05-11"
