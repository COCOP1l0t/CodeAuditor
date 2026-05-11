from __future__ import annotations

import json
from pathlib import Path

from code_auditor.discovered import (
    append_entries,
    build_dedupe_key,
    build_discovered_entry,
    collect_repo_snapshot,
    read_discovered_keys,
)


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


def test_read_discovered_keys_returns_empty_set_for_missing_file(tmp_path: Path) -> None:
    assert read_discovered_keys(str(tmp_path / "missing.md")) == set()


def test_read_discovered_keys_parses_entries_and_ignores_malformed_json(tmp_path: Path) -> None:
    path = tmp_path / "bugs.md"
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
    path = tmp_path / "nested" / "bugs.md"

    append_entries(str(path), ["## Bug One\n\nDetails\n", "## Bug Two\n\nDetails\n"])

    content = path.read_text(encoding="utf-8")
    assert content.startswith("# Reproduced Bugs\n\n")
    assert "Details\n\n## Bug Two" in content
    assert content.endswith("Details\n")


def test_build_discovered_entry_includes_visible_fields_and_relative_links(tmp_path: Path) -> None:
    discovered_path = tmp_path / "target" / "reproduced-bugs.md"
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

    assert "## Length underflow reaches memcpy" in entry
    assert "**Repository:** https://example.test/repo.git" in entry
    assert "**Version:** 1.2.3" in entry
    assert "**Audited Commit:** `abcdef123456`" in entry
    assert "**Audit Finished:** 2026-05-11" in entry
    assert "**Severity:** High / CVSS 8.1" in entry
    assert "**CWE:** CWE-191" in entry
    assert "**Location:** `src/parser.c:parse_packet lines 10-24`" in entry
    assert "Remote denial of service." in entry
    assert "[Stage 4 Finding](audit-output/stage4-vulnerabilities/H-01.json)" in entry
    assert "[Stage 5 Report](audit-output/stage5-pocs/H-01/report.md)" in entry
    assert "[Stage 6 Report](audit-output/stage6-disclosures/H-01/disclosure/report.md)" in entry
    assert "[Stage 6 Email](audit-output/stage6-disclosures/H-01/disclosure/email.md)" in entry
    assert "[Stage 6 Zip](audit-output/stage6-disclosures/H-01/disclosure/poc.zip)" in entry

    metadata_line = next(line for line in entry.splitlines() if line.startswith("<!-- code-auditor:discovered "))
    payload = metadata_line.removeprefix("<!-- code-auditor:discovered ").removesuffix(" -->")
    metadata = json.loads(payload)
    assert metadata["dedupe_key"].startswith("sha256:")
    assert metadata["title"] == "Length underflow reaches memcpy"
    assert metadata["repo_url"] == "https://example.test/repo.git"
    assert metadata["audited_commit"] == "abcdef123456"
    assert metadata["audit_finished_date"] == "2026-05-11"


def test_build_discovered_entry_uses_absolute_link_for_unrelated_artifact_path(tmp_path: Path) -> None:
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
        discovered_path=str(tmp_path / "target" / "reproduced-bugs.md"),
        stage5_report_path="/var/lib/code-auditor/stage5/report.md",
    )

    assert "[Stage 5 Report](/var/lib/code-auditor/stage5/report.md)" in entry


def test_collect_repo_snapshot_handles_non_git_target_without_raising(tmp_path: Path) -> None:
    snapshot = collect_repo_snapshot(str(tmp_path), audit_finished_date="2026-05-11")

    assert snapshot["target_path"] == str(tmp_path)
    assert snapshot["repo_url"] == ""
    assert snapshot["audited_commit"] == ""
    assert snapshot["dirty_status"] == "unknown"
    assert snapshot["audit_finished_date"] == "2026-05-11"
