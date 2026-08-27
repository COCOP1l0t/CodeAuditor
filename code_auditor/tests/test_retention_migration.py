from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from code_auditor.retention_migration import (
    RetentionMigrationError,
    apply_retention_entrypoint_repairs,
    apply_retention_manifests,
    build_retention_entrypoint_repair_report,
    build_retention_migration_report,
)
from code_auditor.retention import RETAIN_MANIFEST_FILENAME, load_retain_manifest
from code_auditor.utils import render_json_report


def _write_artifact(root: Path, *, disposable_reference: bool = False) -> None:
    root.mkdir(parents=True)
    script = root / "reproduce.sh"
    body = "#!/bin/sh\nexec echo reproduced\n"
    if disposable_reference:
        body = "#!/bin/sh\nexec /tmp/code-auditor/old/build/poc\n"
    script.write_text(body, encoding="utf-8")
    script.chmod(0o700)
    (root / "report.md").write_text("# Report\n", encoding="utf-8")
    build = root / "build-debug"
    build.mkdir()
    (build / "large.o").write_bytes(b"x" * 8192)


def _write_disclosure(root: Path) -> None:
    _write_artifact(root)
    (root / "email.txt").write_text("Disclosure email\n", encoding="utf-8")
    (root / "disclosure.zip").write_bytes(b"PK\x05\x06" + b"\0" * 18)


def _replace_with_legacy_entrypoint(
    root: Path,
    *,
    name: str = "run_poc.sh",
    body: str = "#!/bin/sh\nexec echo legacy \"$@\"\n",
) -> Path:
    (root / "reproduce.sh").unlink()
    legacy = root / name
    legacy.write_text(body, encoding="utf-8")
    legacy.chmod(0o700)
    return legacy


def _write_runs_db(path: Path, active_output: Path | None = None) -> None:
    with sqlite3.connect(path) as connection:
        connection.execute("CREATE TABLE runs (output_dir TEXT, status TEXT)")
        if active_output is not None:
            connection.execute(
                "INSERT INTO runs VALUES (?, 'running')",
                (str(active_output),),
            )


def _write_poc_status_db(
    path: Path,
    output: Path,
    *,
    vuln_id: str = "H-01",
    poc_status: str | None = "reproduced",
) -> None:
    with sqlite3.connect(path) as connection:
        connection.execute(
            "CREATE TABLE runs (id INTEGER PRIMARY KEY, output_dir TEXT, status TEXT)"
        )
        connection.execute(
            "CREATE TABLE pocs (run_id INTEGER, vuln_id TEXT, status TEXT)"
        )
        connection.execute(
            "INSERT INTO runs VALUES (1, ?, 'done')",
            (str(output),),
        )
        if poc_status is not None:
            connection.execute(
                "INSERT INTO pocs VALUES (1, ?, ?)",
                (vuln_id, poc_status),
            )


def test_history_migration_is_dry_run_and_blocks_active_outputs(
    tmp_path: Path,
) -> None:
    results = tmp_path / "results"
    inactive = results / "project" / "audit-output-inactive"
    active = results / "project" / "audit-output-active"
    _write_artifact(inactive / "stage5-pocs" / "H-01")
    _write_artifact(active / "stage5-pocs" / "H-02")
    (inactive / ".poc-worktree").mkdir(parents=True)
    (inactive / ".poc-worktree" / "object.o").write_bytes(b"temporary")
    stage6_vuln = inactive / "stage6-disclosures" / "H-01"
    _write_disclosure(stage6_vuln / "disclosure")
    (stage6_vuln / "agent.log").write_text("old log", encoding="utf-8")
    db = tmp_path / "history.db"
    _write_runs_db(db, active)
    before = sorted(str(path.relative_to(results)) for path in results.rglob("*"))

    report = build_retention_migration_report(results, db_path=db)
    rendered = render_json_report(report)
    after = sorted(str(path.relative_to(results)) for path in results.rglob("*"))

    assert json.loads(rendered) == report
    assert report["mode"] == "dry-run"
    assert report["mutations"] == []
    assert before == after
    assert report["database"]["verified"] is True
    plans = {Path(item["path"]).name: item for item in report["outputs"]}
    assert plans["audit-output-inactive"]["artifacts"][0]["ready"] is True
    active_artifact = plans["audit-output-active"]["artifacts"][0]
    assert active_artifact["ready"] is False
    assert {item["type"] for item in active_artifact["blockers"]} == {
        "active_output"
    }
    stage6_intermediates = [
        item
        for item in plans["audit-output-inactive"]["disposable_roots"]
        if item.get("kind") == "stage6-non-disclosure-intermediate"
    ]
    assert [Path(item["path"]).name for item in stage6_intermediates] == [
        "agent.log"
    ]
    assert all(item["ready"] for item in stage6_intermediates)
    assert report["summary"]["estimated_safe_reclaimable_bytes"] > 0


def test_history_migration_fails_closed_when_database_is_missing(
    tmp_path: Path,
) -> None:
    results = tmp_path / "results"
    artifact = results / "project" / "audit-output-one" / "stage5-pocs" / "H-01"
    _write_artifact(artifact)

    report = build_retention_migration_report(
        results,
        db_path=tmp_path / "missing.db",
    )

    assert report["database"]["verified"] is False
    assert report["outputs"][0]["artifacts"][0]["ready"] is False
    assert report["outputs"][0]["artifacts"][0]["blockers"][-1] == {
        "type": "database_state_unknown"
    }
    assert report["summary"]["estimated_safe_reclaimable_bytes"] == 0


def test_history_migration_exempts_database_confirmed_nonreproduced_artifact(
    tmp_path: Path,
) -> None:
    results = tmp_path / "results"
    output = results / "project" / "audit-output-one"
    artifact = output / "stage5-pocs" / "H-01"
    _write_artifact(artifact)
    (artifact / "reproduce.sh").unlink()
    db = tmp_path / "history.db"
    _write_poc_status_db(db, output, poc_status="not-reproduced")

    report = build_retention_migration_report(results, db_path=db)
    plan = report["outputs"][0]["artifacts"][0]

    assert plan["migration_required"] is False
    assert plan["migration_state"] == "exempt-not-reproduced"
    assert plan["ignored_blockers"] == [{"type": "missing_reproduce_sh"}]
    assert report["summary"]["migration_required_artifact_count"] == 0
    assert report["summary"]["exempt_not_reproduced_artifact_count"] == 1
    assert report["summary"]["blocked_artifact_count"] == 0
    repair = build_retention_entrypoint_repair_report(results, db_path=db)
    assert repair["repairs"] == []
    assert repair["blocked_artifacts"] == []


def test_history_migration_blocks_unmapped_artifact_when_status_gate_exists(
    tmp_path: Path,
) -> None:
    results = tmp_path / "results"
    output = results / "project" / "audit-output-one"
    artifact = output / "stage5-pocs" / "H-01"
    _write_artifact(artifact)
    db = tmp_path / "history.db"
    _write_poc_status_db(db, output, poc_status=None)

    report = build_retention_migration_report(results, db_path=db)
    plan = report["outputs"][0]["artifacts"][0]

    assert plan["migration_required"] is True
    assert plan["migration_state"] == "blocked-unmapped-poc-status"
    assert {item["type"] for item in plan["blockers"]} == {
        "poc_status_unmapped"
    }


def test_history_migration_supersedes_blocked_stage5_only_after_stage6_manifest(
    tmp_path: Path,
) -> None:
    results = tmp_path / "results"
    output = results / "project" / "audit-output-one"
    stage5 = output / "stage5-pocs" / "H-01"
    stage6 = output / "stage6-disclosures" / "H-01" / "disclosure"
    _write_artifact(stage5)
    (stage5 / "reproduce.sh").unlink()
    _write_disclosure(stage6)
    db = tmp_path / "history.db"
    _write_poc_status_db(db, output)

    before = build_retention_migration_report(results, db_path=db)
    before_stage5 = next(
        item for item in before["outputs"][0]["artifacts"] if item["kind"] == "stage5"
    )
    assert before_stage5["migration_required"] is True
    assert before_stage5["ready"] is False
    assert before["summary"]["superseded_stage5_artifact_count"] == 0

    applied = apply_retention_manifests(results, db_path=db)
    assert applied["mutations"] == [
        {"action": "create", "path": str(stage6 / RETAIN_MANIFEST_FILENAME)}
    ]

    after = build_retention_migration_report(results, db_path=db)
    after_stage5 = next(
        item for item in after["outputs"][0]["artifacts"] if item["kind"] == "stage5"
    )
    assert after_stage5["migration_required"] is False
    assert after_stage5["migration_state"] == "superseded-by-stage6"
    assert after_stage5["superseded_by"] == str(stage6)
    assert after_stage5["ignored_blockers"] == [{"type": "missing_reproduce_sh"}]
    assert after["summary"]["superseded_stage5_artifact_count"] == 1


def test_history_migration_reports_nonportable_script_blocker(
    tmp_path: Path,
) -> None:
    results = tmp_path / "results"
    artifact = results / "project" / "audit-output-one" / "stage5-pocs" / "H-01"
    _write_artifact(artifact, disposable_reference=True)
    worktree = artifact.parents[1] / ".poc-worktree"
    worktree.mkdir()
    (worktree / "object.o").write_bytes(b"temporary")
    db = tmp_path / "history.db"
    _write_runs_db(db)

    report = build_retention_migration_report(results, db_path=db)

    blockers = report["outputs"][0]["artifacts"][0]["blockers"]
    assert any(item["type"] == "disposable_path_reference" for item in blockers)
    disposable = report["outputs"][0]["disposable_roots"][0]
    assert disposable["ready"] is False
    assert disposable["blocker"] == "artifact_migration_blocked"


def test_history_migration_allows_checkout_local_target_debug_reference(
    tmp_path: Path,
) -> None:
    results = tmp_path / "results"
    output = results / "project" / "audit-output-one"
    artifact = output / "stage5-pocs" / "H-01"
    _write_artifact(artifact)
    (artifact / "reproduce.sh").write_text(
        "#!/bin/sh\nset -eu\ncargo build\nexec ./target/debug/reproducer\n",
        encoding="utf-8",
    )
    (artifact / "reproduce.sh").chmod(0o700)
    db = tmp_path / "history.db"
    _write_runs_db(db)

    report = build_retention_migration_report(results, db_path=db)

    assert report["outputs"][0]["artifacts"][0]["ready"] is True


def test_history_migration_treats_evidence_paths_as_nonportable_records(
    tmp_path: Path,
) -> None:
    results = tmp_path / "results"
    output = results / "project" / "audit-output-one"
    artifact = output / "stage5-pocs" / "H-01"
    _write_artifact(artifact)
    evidence = artifact / "evidence" / "observed.json"
    evidence.parent.mkdir()
    evidence.write_text(
        '{"old_path":"/tmp/code-auditor/finished/target"}\n',
        encoding="utf-8",
    )
    db = tmp_path / "history.db"
    _write_runs_db(db)

    report = build_retention_migration_report(results, db_path=db)
    plan = report["outputs"][0]["artifacts"][0]

    assert plan["ready"] is True
    assert next(
        item
        for item in plan["candidate_files"]
        if item["path"] == "evidence/observed.json"
    )["role"] == "evidence"


def test_history_migration_does_not_treat_historical_report_path_as_runtime_use(
    tmp_path: Path,
) -> None:
    results = tmp_path / "results"
    artifact = results / "project" / "audit-output-one" / "stage5-pocs" / "H-01"
    _write_artifact(artifact)
    (artifact / "report.md").write_text(
        "Historical build: /tmp/code-auditor/old/build/poc\n",
        encoding="utf-8",
    )
    db = tmp_path / "history.db"
    _write_runs_db(db)

    report = build_retention_migration_report(results, db_path=db)

    artifact_plan = report["outputs"][0]["artifacts"][0]
    assert artifact_plan["ready"] is True
    assert not any(
        item["type"] == "disposable_path_reference"
        for item in artifact_plan["blockers"]
    )


def test_history_migration_skips_generated_trees_but_keeps_builder_source(
    tmp_path: Path,
) -> None:
    results = tmp_path / "results"
    artifact = results / "project" / "audit-output-one" / "stage5-pocs" / "H-01"
    _write_artifact(artifact)
    generated = [
        artifact / ".dart_tool" / "generated.py",
        artifact / ".gradle" / "generated.py",
        artifact / "deps" / "generated.py",
        artifact / "harness" / "obj" / "generated.json",
        artifact / "qemu-bundle" / "generated.py",
    ]
    for path in generated:
        path.parent.mkdir(parents=True)
        path.write_text("generated\n", encoding="utf-8")
    source = artifact / "crate" / "src" / "builder" / "mod.rs"
    source.parent.mkdir(parents=True)
    source.write_text("pub struct Builder;\n", encoding="utf-8")
    db = tmp_path / "history.db"
    _write_runs_db(db)

    report = build_retention_migration_report(results, db_path=db)

    candidate_paths = {
        item["path"]
        for item in report["outputs"][0]["artifacts"][0]["candidate_files"]
    }
    assert "crate/src/builder/mod.rs" in candidate_paths
    assert not candidate_paths.intersection(
        {path.relative_to(artifact).as_posix() for path in generated}
    )


def test_history_migration_keeps_virtualization_reproduction_inputs(
    tmp_path: Path,
) -> None:
    results = tmp_path / "results"
    artifact = results / "project" / "audit-output-one" / "stage5-pocs" / "H-01"
    _write_artifact(artifact)
    for name in ("malicious.ovf", "state.sav", "disk.vhdx", "stream.mig"):
        (artifact / name).write_bytes(b"input")
    db = tmp_path / "history.db"
    _write_runs_db(db)

    report = build_retention_migration_report(results, db_path=db)

    candidates = {
        item["path"]: item["role"]
        for item in report["outputs"][0]["artifacts"][0]["candidate_files"]
    }
    assert candidates["malicious.ovf"] == "support"
    assert candidates["state.sav"] == "input"
    assert candidates["disk.vhdx"] == "input"
    assert candidates["stream.mig"] == "input"


def test_history_migration_rejects_symlink_results_root(tmp_path: Path) -> None:
    results = tmp_path / "results"
    results.mkdir()
    alias = tmp_path / "results-alias"
    alias.symlink_to(results, target_is_directory=True)

    with pytest.raises(RetentionMigrationError, match="cannot be a symlink"):
        build_retention_migration_report(alias)


def test_manifest_apply_creates_only_manifest_and_is_idempotent(
    tmp_path: Path,
) -> None:
    results = tmp_path / "results"
    artifact = results / "project" / "audit-output-one" / "stage5-pocs" / "H-01"
    _write_artifact(artifact)
    db = tmp_path / "history.db"
    _write_runs_db(db)
    before = sorted(path.relative_to(artifact) for path in artifact.rglob("*"))
    planned_safe_bytes = build_retention_migration_report(
        results,
        db_path=db,
    )["summary"]["estimated_safe_reclaimable_bytes"]

    report = apply_retention_manifests(results, db_path=db)

    assert report["mode"] == "apply-manifests"
    assert report["summary"]["estimated_safe_reclaimable_bytes"] == planned_safe_bytes
    assert report["mutations"] == [
        {
            "action": "create",
            "path": str(artifact / RETAIN_MANIFEST_FILENAME),
        }
    ]
    load_retain_manifest(
        artifact,
        required_paths=("report.md", "reproduce.sh"),
    )
    assert (artifact / "build-debug" / "large.o").is_file()
    assert sorted(
        path.relative_to(artifact)
        for path in artifact.rglob("*")
        if path.name != RETAIN_MANIFEST_FILENAME
    ) == before

    second = apply_retention_manifests(results, db_path=db)
    assert second["mutations"] == []


def test_manifest_apply_repairs_invalid_manifest(tmp_path: Path) -> None:
    results = tmp_path / "results"
    artifact = results / "project" / "audit-output-one" / "stage5-pocs" / "H-01"
    _write_artifact(artifact)
    (artifact / RETAIN_MANIFEST_FILENAME).write_text("{}\n", encoding="utf-8")
    db = tmp_path / "history.db"
    _write_runs_db(db)

    report = apply_retention_manifests(results, db_path=db)

    assert report["mutations"][0]["action"] == "repair"
    load_retain_manifest(artifact)


def test_manifest_apply_refuses_unverified_database(tmp_path: Path) -> None:
    results = tmp_path / "results"
    artifact = results / "project" / "audit-output-one" / "stage5-pocs" / "H-01"
    _write_artifact(artifact)

    with pytest.raises(RetentionMigrationError, match="verified audit database"):
        apply_retention_manifests(results, db_path=tmp_path / "missing.db")

    assert not (artifact / RETAIN_MANIFEST_FILENAME).exists()


def test_stage6_manifest_requires_complete_disclosure_bundle(tmp_path: Path) -> None:
    results = tmp_path / "results"
    artifact = (
        results
        / "project"
        / "audit-output-one"
        / "stage6-disclosures"
        / "H-01"
        / "disclosure"
    )
    _write_artifact(artifact)
    db = tmp_path / "history.db"
    _write_runs_db(db)

    report = build_retention_migration_report(results, db_path=db)

    blockers = report["outputs"][0]["artifacts"][0]["blockers"]
    assert {item["type"] for item in blockers} == {
        "missing_disclosure_zip",
        "missing_email",
    }


def test_history_migration_ignores_empty_artifact_directories(
    tmp_path: Path,
) -> None:
    results = tmp_path / "results"
    output = results / "project" / "audit-output-one"
    (output / "stage5-pocs" / "H-01").mkdir(parents=True)
    (output / "stage6-disclosures" / "H-02" / "disclosure").mkdir(
        parents=True
    )
    db = tmp_path / "history.db"
    _write_runs_db(db)

    report = build_retention_migration_report(results, db_path=db)

    assert report["summary"]["artifact_count"] == 0
    assert report["summary"]["blocked_artifact_count"] == 0
    assert report["outputs"][0]["artifacts"] == []


def test_entrypoint_repair_dry_run_finds_unambiguous_portable_legacy_script(
    tmp_path: Path,
) -> None:
    results = tmp_path / "results"
    artifact = results / "project" / "audit-output-one" / "stage5-pocs" / "H-01"
    _write_artifact(artifact)
    legacy = _replace_with_legacy_entrypoint(artifact)
    db = tmp_path / "history.db"
    _write_runs_db(db)

    report = build_retention_entrypoint_repair_report(results, db_path=db)

    assert report["summary"] == {
        "missing_entrypoint_count": 1,
        "auto_repairable_count": 1,
        "manual_repair_count": 0,
        "blocked_artifact_count": 1,
        "portability_blocked_count": 0,
        "invalid_manifest_count": 0,
    }
    assert report["repairs"][0]["action"] == "create-wrapper"
    assert report["repairs"][0]["legacy_entrypoints"][0]["name"] == legacy.name
    assert not (artifact / "reproduce.sh").exists()
    assert report["mutations"] == []


def test_entrypoint_repair_apply_creates_wrapper_and_manifest_idempotently(
    tmp_path: Path,
) -> None:
    results = tmp_path / "results"
    artifact = results / "project" / "audit-output-one" / "stage5-pocs" / "H-01"
    _write_artifact(artifact)
    _replace_with_legacy_entrypoint(artifact)
    db = tmp_path / "history.db"
    _write_runs_db(db)

    report = apply_retention_entrypoint_repairs(results, db_path=db)

    wrapper = artifact / "reproduce.sh"
    assert wrapper.read_text(encoding="utf-8") == (
        "#!/bin/sh\n"
        "set -eu\n"
        'SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)\n'
        'exec "$SCRIPT_DIR/run_poc.sh" "$@"\n'
    )
    assert wrapper.stat().st_mode & 0o100
    load_retain_manifest(artifact, required_paths=("report.md", "reproduce.sh"))
    assert report["summary"]["entrypoint_mutation_count"] == 1
    assert report["summary"]["manifest_mutation_count"] == 1
    assert len(report["mutations"]) == 2

    second = apply_retention_entrypoint_repairs(results, db_path=db)
    assert second["mutations"] == []
    assert second["summary"]["entrypoint_mutation_count"] == 0
    assert second["summary"]["manifest_mutation_count"] == 0


def test_entrypoint_repair_blocks_nonportable_and_ambiguous_legacy_scripts(
    tmp_path: Path,
) -> None:
    results = tmp_path / "results"
    output = results / "project" / "audit-output-one"
    nonportable = output / "stage5-pocs" / "H-01"
    ambiguous = output / "stage5-pocs" / "H-02"
    _write_artifact(nonportable)
    _replace_with_legacy_entrypoint(
        nonportable,
        body="#!/bin/sh\nexec /tmp/code-auditor/old/build/poc\n",
    )
    _write_artifact(ambiguous)
    _replace_with_legacy_entrypoint(ambiguous)
    second = ambiguous / "poc.sh"
    second.write_text("#!/bin/sh\nexec echo second\n", encoding="utf-8")
    second.chmod(0o700)
    db = tmp_path / "history.db"
    _write_runs_db(db)

    report = build_retention_entrypoint_repair_report(results, db_path=db)

    repairs = {Path(item["path"]).name: item for item in report["repairs"]}
    first_blockers = repairs["H-01"]["blockers"]
    assert {item.get("blocker") for item in first_blockers} == {
        "disposable_path_reference"
    }
    second_types = {item["type"] for item in repairs["H-02"]["blockers"]}
    assert second_types == {"ambiguous_legacy_entrypoint"}
    assert report["summary"]["auto_repairable_count"] == 0


def test_entrypoint_repair_accepts_unique_script_invoked_by_report(
    tmp_path: Path,
) -> None:
    results = tmp_path / "results"
    artifact = results / "project" / "audit-output-one" / "stage5-pocs" / "H-01"
    _write_artifact(artifact)
    (artifact / "reproduce.sh").unlink()
    script = artifact / "poc_case.py"
    script.write_text("#!/usr/bin/env python3\nprint('reproduced')\n", encoding="utf-8")
    script.chmod(0o700)
    (artifact / "report.md").write_text(
        "Run the reproducer with `./poc_case.py`.\n",
        encoding="utf-8",
    )
    db = tmp_path / "history.db"
    _write_runs_db(db)

    dry_run = build_retention_entrypoint_repair_report(results, db_path=db)

    candidate = dry_run["repairs"][0]["legacy_entrypoints"][0]
    assert candidate["name"] == "poc_case.py"
    assert candidate["source"] == "report-invocation"
    assert dry_run["repairs"][0]["ready"] is True

    apply_retention_entrypoint_repairs(results, db_path=db)
    assert 'exec "$SCRIPT_DIR/poc_case.py" "$@"' in (
        artifact / "reproduce.sh"
    ).read_text(encoding="utf-8")


def test_entrypoint_repair_accepts_unique_executable_reproduction_named_script(
    tmp_path: Path,
) -> None:
    results = tmp_path / "results"
    artifact = results / "project" / "audit-output-one" / "stage5-pocs" / "H-01"
    _write_artifact(artifact)
    (artifact / "reproduce.sh").unlink()
    script = artifact / "poc_case.py"
    script.write_text("#!/usr/bin/env python3\nprint('reproduced')\n", encoding="utf-8")
    script.chmod(0o700)
    db = tmp_path / "history.db"
    _write_runs_db(db)

    report = build_retention_entrypoint_repair_report(results, db_path=db)

    candidate = report["repairs"][0]["legacy_entrypoints"][0]
    assert candidate["name"] == "poc_case.py"
    assert candidate["source"] == "unique-reproduction-script"
    assert report["repairs"][0]["ready"] is True


def test_entrypoint_repair_accepts_unique_nested_recognized_script(
    tmp_path: Path,
) -> None:
    results = tmp_path / "results"
    artifact = results / "project" / "audit-output-one" / "stage5-pocs" / "H-01"
    _write_artifact(artifact)
    (artifact / "reproduce.sh").unlink()
    script = artifact / "poc" / "run_poc.sh"
    script.parent.mkdir()
    script.write_text("#!/bin/sh\nset -eu\necho reproduced\n", encoding="utf-8")
    script.chmod(0o700)
    db = tmp_path / "history.db"
    _write_runs_db(db)

    report = build_retention_entrypoint_repair_report(results, db_path=db)

    candidate = report["repairs"][0]["legacy_entrypoints"][0]
    assert candidate["name"] == "poc/run_poc.sh"
    assert candidate["source"] == "recognized-nested-name"
    assert report["repairs"][0]["ready"] is True


def test_entrypoint_repair_invokes_nonexecutable_script_through_shebang_runtime(
    tmp_path: Path,
) -> None:
    results = tmp_path / "results"
    artifact = results / "project" / "audit-output-one" / "stage5-pocs" / "H-01"
    _write_artifact(artifact)
    (artifact / "reproduce.sh").unlink()
    script = artifact / "poc_case.py"
    script.write_text("#!/usr/bin/env python3\nprint('reproduced')\n", encoding="utf-8")
    script.chmod(0o600)
    db = tmp_path / "history.db"
    _write_runs_db(db)

    dry_run = build_retention_entrypoint_repair_report(results, db_path=db)

    candidate = dry_run["repairs"][0]["legacy_entrypoints"][0]
    assert candidate["executable"] is False
    assert candidate["interpreter"] == "python3"
    assert dry_run["repairs"][0]["ready"] is True

    apply_retention_entrypoint_repairs(results, db_path=db)
    assert 'exec python3 "$SCRIPT_DIR/poc_case.py" "$@"' in (
        artifact / "reproduce.sh"
    ).read_text(encoding="utf-8")
