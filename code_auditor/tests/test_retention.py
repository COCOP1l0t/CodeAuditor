from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from code_auditor.retention import (
    RETAIN_MANIFEST_FILENAME,
    RetentionError,
    export_retained_artifacts,
    load_retain_manifest,
    secure_generated_manifest_mode,
)


def _write_retained_tree(root: Path) -> None:
    root.mkdir(parents=True)
    entrypoint = root / "reproduce.sh"
    entrypoint.write_text("#!/bin/sh\nexec echo reproduced\n", encoding="utf-8")
    entrypoint.chmod(0o700)
    (root / "report.md").write_text("# Reproduction\n", encoding="utf-8")
    (root / "build").mkdir()
    (root / "build" / "large-object.o").write_bytes(b"temporary")
    manifest_path = root / RETAIN_MANIFEST_FILENAME
    manifest_path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "entrypoint": "reproduce.sh",
                "files": [
                    {"path": "reproduce.sh", "role": "entrypoint"},
                    {"path": "report.md", "role": "report"},
                ],
            }
        ),
        encoding="utf-8",
    )
    manifest_path.chmod(0o600)


def test_export_retained_artifacts_replaces_destination_with_manifest_only(
    tmp_path: Path,
) -> None:
    source = tmp_path / "scratch"
    destination = tmp_path / "persistent" / "H-01"
    _write_retained_tree(source)
    destination.mkdir(parents=True)
    (destination / "stale-build.bin").write_bytes(b"old")

    manifest = export_retained_artifacts(
        source,
        destination,
        required_paths=("reproduce.sh", "report.md"),
    )

    assert manifest.entrypoint == "reproduce.sh"
    assert sorted(path.name for path in destination.iterdir()) == [
        "report.md",
        "reproduce.sh",
        RETAIN_MANIFEST_FILENAME,
    ]
    assert os.access(destination / "reproduce.sh", os.X_OK)
    assert not (destination / "build").exists()


def test_export_retained_artifacts_compacts_source_in_place(tmp_path: Path) -> None:
    artifact = tmp_path / "H-01"
    _write_retained_tree(artifact)

    manifest = export_retained_artifacts(
        artifact,
        artifact,
        required_paths=("reproduce.sh", "report.md"),
    )

    assert manifest.entrypoint == "reproduce.sh"
    assert sorted(path.name for path in artifact.iterdir()) == [
        "report.md",
        "reproduce.sh",
        RETAIN_MANIFEST_FILENAME,
    ]
    assert load_retain_manifest(
        artifact,
        required_paths=("reproduce.sh", "report.md"),
    ) == manifest


@pytest.mark.parametrize(
    "bad_script",
    [
        "#!/bin/sh\n/tmp/code-auditor/task/build/poc\n",
        "#!/bin/sh\nexec .poc-worktree/build/poc\n",
        "#!/bin/sh\nexec ./qemu-worktree/build/poc\n",
        "#!/bin/sh\nexec /var/lib/toolchain/bin/clang\n",
    ],
)
def test_manifest_rejects_disposable_path_references(
    tmp_path: Path,
    bad_script: str,
) -> None:
    source = tmp_path / "scratch"
    _write_retained_tree(source)
    (source / "reproduce.sh").write_text(bad_script, encoding="utf-8")

    with pytest.raises(RetentionError, match="references disposable"):
        load_retain_manifest(source)


def test_manifest_rejects_hardlinked_files(tmp_path: Path) -> None:
    source = tmp_path / "scratch"
    _write_retained_tree(source)
    os.link(source / "report.md", source / "report-copy.md")

    with pytest.raises(RetentionError, match="must not be hard-linked"):
        load_retain_manifest(source)


def test_manifest_rejects_group_or_world_access(tmp_path: Path) -> None:
    source = tmp_path / "scratch"
    _write_retained_tree(source)
    (source / RETAIN_MANIFEST_FILENAME).chmod(0o644)

    with pytest.raises(RetentionError, match="group/world accessible"):
        load_retain_manifest(source)


def test_secure_generated_manifest_mode_tightens_regular_file(tmp_path: Path) -> None:
    source = tmp_path / "scratch"
    _write_retained_tree(source)
    manifest_path = source / RETAIN_MANIFEST_FILENAME
    manifest_path.chmod(0o644)

    assert secure_generated_manifest_mode(source) is True
    assert manifest_path.stat().st_mode & 0o777 == 0o600
    assert load_retain_manifest(source).entrypoint == "reproduce.sh"


def test_secure_generated_manifest_mode_rejects_hardlink(tmp_path: Path) -> None:
    source = tmp_path / "scratch"
    _write_retained_tree(source)
    os.link(source / RETAIN_MANIFEST_FILENAME, tmp_path / "manifest-copy.json")

    assert secure_generated_manifest_mode(source) is False


def test_manifest_rejects_nonportable_support_file(tmp_path: Path) -> None:
    source = tmp_path / "scratch"
    _write_retained_tree(source)
    (source / "config.json").write_text(
        '{"binary": "/tmp/code-auditor/task/build/poc"}', encoding="utf-8"
    )
    manifest_path = source / RETAIN_MANIFEST_FILENAME
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["files"].append({"path": "config.json", "role": "support"})
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(RetentionError, match="references disposable"):
        load_retain_manifest(source)


def test_manifest_allows_bounded_binary_reproduction_input(tmp_path: Path) -> None:
    source = tmp_path / "scratch"
    _write_retained_tree(source)
    (source / "state.sav").write_bytes(b"\0binary-state")
    manifest_path = source / RETAIN_MANIFEST_FILENAME
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["files"].append({"path": "state.sav", "role": "input"})
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    loaded = load_retain_manifest(source)

    assert any(item.path == "state.sav" for item in loaded.files)


def test_manifest_allows_historical_disposable_path_in_report(tmp_path: Path) -> None:
    source = tmp_path / "scratch"
    _write_retained_tree(source)
    (source / "report.md").write_text(
        "Historical command: /tmp/code-auditor/task/build/poc\n",
        encoding="utf-8",
    )

    manifest = load_retain_manifest(source)

    assert any(item.path == "report.md" for item in manifest.files)


def test_manifest_requires_executable_shebang_entrypoint(tmp_path: Path) -> None:
    source = tmp_path / "scratch"
    _write_retained_tree(source)
    (source / "reproduce.sh").write_text("echo no-shebang\n", encoding="utf-8")
    (source / "reproduce.sh").chmod(0o600)

    with pytest.raises(RetentionError, match="shebang"):
        load_retain_manifest(source)


def test_export_rejects_symlink_destination_parent(tmp_path: Path) -> None:
    source = tmp_path / "scratch"
    _write_retained_tree(source)
    outside = tmp_path / "outside"
    outside.mkdir()
    linked_parent = tmp_path / "results"
    linked_parent.symlink_to(outside, target_is_directory=True)

    with pytest.raises(RetentionError, match="destination parent"):
        export_retained_artifacts(source, linked_parent / "H-01")

    assert list(outside.iterdir()) == []
