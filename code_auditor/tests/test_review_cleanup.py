from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from code_auditor.review_cleanup import (
    ReviewedCleanupError,
    apply_reviewed_cleanup,
    build_reviewed_cleanup_report,
)


def _write_database(
    path: Path,
    output: Path,
    entries: list[tuple[str, str | None, str]],
    *,
    running: bool = False,
    registered_report: str | None = None,
) -> None:
    with sqlite3.connect(path) as connection:
        connection.executescript(
            """
            CREATE TABLE runs (id INTEGER, output_dir TEXT, status TEXT);
            CREATE TABLE vulnerabilities (
                run_id INTEGER, vuln_id TEXT, dedupe_key TEXT
            );
            CREATE TABLE pocs (
                run_id INTEGER, vuln_id TEXT, status TEXT,
                report_path TEXT, trigger_graph_path TEXT, asan_report_path TEXT
            );
            CREATE TABLE disclosures (
                run_id INTEGER, vuln_id TEXT, report_path TEXT,
                email_path TEXT, zip_path TEXT
            );
            CREATE TABLE disclosed_bugs (
                dedupe_key TEXT, review_status TEXT, artifact_links TEXT
            );
            """
        )
        connection.execute(
            "INSERT INTO runs VALUES (1, ?, ?)",
            (str(output), "running" if running else "done"),
        )
        for index, (vuln_id, review_status, poc_status) in enumerate(entries):
            dedupe_key = f"key-{index}"
            connection.execute(
                "INSERT INTO vulnerabilities VALUES (1, ?, ?)",
                (vuln_id, dedupe_key),
            )
            report_path = registered_report or f"stage5-pocs/{vuln_id}/report.md"
            connection.execute(
                "INSERT INTO pocs VALUES (1, ?, ?, ?, '', '')",
                (vuln_id, poc_status, report_path),
            )
            if review_status is not None:
                connection.execute(
                    "INSERT INTO disclosed_bugs VALUES (?, ?, '[]')",
                    (dedupe_key, review_status),
                )


def _write_artifact(output: Path, vuln_id: str) -> Path:
    artifact = output / "stage5-pocs" / vuln_id
    artifact.mkdir(parents=True)
    (artifact / "report.md").write_text("# Report\n", encoding="utf-8")
    build = artifact / "build-asan"
    build.mkdir()
    (build / "large.o").write_bytes(b"x" * 8192)
    return artifact


def test_reviewed_cleanup_apply_deletes_only_compilation_directory(
    tmp_path: Path,
) -> None:
    results = tmp_path / "results"
    output = results / "project" / "audit-output-one"
    artifact = _write_artifact(output, "H-01")
    db = tmp_path / "audits.db"
    _write_database(db, output, [("H-01", "reported", "reproduced")])

    dry_run = build_reviewed_cleanup_report(results, db_path=db)

    assert dry_run["summary"]["cleanup_target_count"] == 1
    assert dry_run["targets"][0]["path"] == str(artifact / "build-asan")
    report = apply_reviewed_cleanup(results, db_path=db)
    assert report["mutations"][0]["action"] == "delete-directory"
    assert not (artifact / "build-asan").exists()
    assert (artifact / "report.md").is_file()
    assert build_reviewed_cleanup_report(results, db_path=db)["targets"] == []


@pytest.mark.parametrize("review_status", ["unreviewed", None])
def test_reviewed_cleanup_fails_closed_for_unreviewed_or_unknown_status(
    tmp_path: Path,
    review_status: str | None,
) -> None:
    results = tmp_path / "results"
    output = results / "project" / "audit-output-one"
    artifact = _write_artifact(output, "H-01")
    db = tmp_path / "audits.db"
    _write_database(db, output, [("H-01", review_status, "reproduced")])

    report = build_reviewed_cleanup_report(results, db_path=db)

    assert report["targets"] == []
    assert (artifact / "build-asan" / "large.o").is_file()


def test_reviewed_cleanup_requires_reproduced_status(tmp_path: Path) -> None:
    results = tmp_path / "results"
    output = results / "project" / "audit-output-one"
    _write_artifact(output, "H-01")
    db = tmp_path / "audits.db"
    _write_database(db, output, [("H-01", "reported", "not-reproduced")])

    report = build_reviewed_cleanup_report(results, db_path=db)

    assert report["targets"] == []
    assert report["summary"]["artifact_status_counts"] == {
        "stage5:not_reproduced": 1
    }


def test_reviewed_cleanup_blocks_registered_file_inside_target(tmp_path: Path) -> None:
    results = tmp_path / "results"
    output = results / "project" / "audit-output-one"
    artifact = _write_artifact(output, "H-01")
    report_in_build = artifact / "build-asan" / "report.md"
    report_in_build.write_text("# Registered\n", encoding="utf-8")
    db = tmp_path / "audits.db"
    _write_database(
        db,
        output,
        [("H-01", "confirmed", "reproduced")],
        registered_report="stage5-pocs/H-01/build-asan/report.md",
    )

    report = build_reviewed_cleanup_report(results, db_path=db)

    assert report["targets"] == []
    assert report["summary"]["blocked_target_count"] == 1
    blocker_types = {
        blocker["type"]
        for blocker in report["blocked_targets"][0]["blockers"]
    }
    assert blocker_types == {"key_filename", "registered_or_retained_path"}


def test_reviewed_cleanup_refuses_active_audit(tmp_path: Path) -> None:
    results = tmp_path / "results"
    output = results / "project" / "audit-output-one"
    _write_artifact(output, "H-01")
    db = tmp_path / "audits.db"
    _write_database(
        db,
        output,
        [("H-01", "reported", "reproduced")],
        running=True,
    )

    with pytest.raises(ReviewedCleanupError, match="while an audit output is active"):
        apply_reviewed_cleanup(results, db_path=db)


def test_shared_worktree_requires_every_artifact_to_be_reviewed(
    tmp_path: Path,
) -> None:
    results = tmp_path / "results"
    output = results / "project" / "audit-output-one"
    first = _write_artifact(output, "H-01")
    _write_artifact(output, "H-02")
    shared = output / ".poc-worktree"
    shared.mkdir()
    (shared / "object.o").write_bytes(b"compiled")
    db = tmp_path / "audits.db"
    _write_database(
        db,
        output,
        [
            ("H-01", "reported", "reproduced"),
            ("H-02", "unreviewed", "reproduced"),
        ],
    )

    report = build_reviewed_cleanup_report(results, db_path=db)

    paths = {item["path"] for item in report["targets"]}
    assert str(first / "build-asan") in paths
    assert str(shared) not in paths


def test_reviewed_cleanup_ignores_symlinked_compile_directory(
    tmp_path: Path,
) -> None:
    results = tmp_path / "results"
    output = results / "project" / "audit-output-one"
    artifact = _write_artifact(output, "H-01")
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "keep").write_text("important", encoding="utf-8")
    (artifact / "build-link").symlink_to(outside, target_is_directory=True)
    db = tmp_path / "audits.db"
    _write_database(db, output, [("H-01", "reported", "reproduced")])

    apply_reviewed_cleanup(results, db_path=db)

    assert (outside / "keep").is_file()
    assert (artifact / "build-link").is_symlink()


def test_reviewed_cleanup_does_not_treat_builder_source_as_build_output(
    tmp_path: Path,
) -> None:
    results = tmp_path / "results"
    output = results / "project" / "audit-output-one"
    artifact = _write_artifact(output, "H-01")
    (artifact / "build-asan").rename(artifact / "compile-results")
    source = artifact / "crate" / "src" / "builder"
    source.mkdir(parents=True)
    (source / "mod.rs").write_text("pub struct Builder;\n", encoding="utf-8")
    db = tmp_path / "audits.db"
    _write_database(db, output, [("H-01", "reported", "reproduced")])

    report = build_reviewed_cleanup_report(results, db_path=db)

    assert report["targets"] == []
    assert (source / "mod.rs").is_file()


def test_reviewed_cleanup_does_not_delete_artifact_source_worktree(
    tmp_path: Path,
) -> None:
    results = tmp_path / "results"
    output = results / "project" / "audit-output-one"
    artifact = _write_artifact(output, "H-01")
    (artifact / "build-asan").rename(artifact / "compile-results")
    worktree = artifact / "qemu-worktree"
    worktree.mkdir()
    (worktree / "source.c").write_text("int main(void) {}\n", encoding="utf-8")
    db = tmp_path / "audits.db"
    _write_database(db, output, [("H-01", "reported", "reproduced")])

    report = build_reviewed_cleanup_report(results, db_path=db)

    assert report["targets"] == []
    assert (worktree / "source.c").is_file()
