"""Regression tests for checkpoint marker naming.

Marker names used to be ``task_key.replace(":", "-")``, which is not injective:
``stage5:H-1:2`` and ``stage5:H-1-2`` produced the same file, so either task
could be skipped as complete or have its marker cleared by the other. Names are
now a reversible encoding (``stage5:H-01`` -> ``stage5--H-01``), and these tests
pin injectivity, path safety, and resume compatibility with markers written by
the old scheme.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from code_auditor.checkpoint import (
    CheckpointManager,
    _decode_marker_name,
    _encode_task_key,
    _legacy_marker_name,
)
from code_auditor.poc_artifacts import validate_vuln_id
from code_auditor.stages import stage5, stage6


def _checkpoint(tmp_path: Path) -> CheckpointManager:
    return CheckpointManager(str(tmp_path), resume=True)


def _marker_name(checkpoint: CheckpointManager, task_key: str) -> str | None:
    path = checkpoint._marker_path(task_key)
    if path is None:
        return None
    assert os.path.dirname(path) == checkpoint._markers_dir
    return os.path.basename(path)


def test_marker_names_are_explicit_and_readable(tmp_path: Path) -> None:
    checkpoint = _checkpoint(tmp_path)

    assert _marker_name(checkpoint, "stage2") == "stage2"
    assert _marker_name(checkpoint, "stage3:AU-1") == "stage3--AU-1"
    assert _marker_name(checkpoint, "stage4:AU-1-F-1.json") == "stage4--AU-1-F-1.json"
    assert _marker_name(checkpoint, "stage5:H-01") == "stage5--H-01"
    assert _marker_name(checkpoint, "stage6:H-01") == "stage6--H-01"
    # A separator inside the suffix is escaped instead of collapsing into the
    # marker of a different task.
    assert _marker_name(checkpoint, "stage5:H-1:2") == "stage5--H-1%3A2"


HOSTILE_KEYS = [
    "stage2",
    "stage3:AU-1",
    "stage4:AU-1-F-1.json",
    "stage5:H-01",
    "stage6:H-01",
    "stage5:H-1:2",
    "stage5:H-1-2",
    "stage5:a:b:c",
    "stage5:../../escape",
    "stage3:AU/1",
    "stage5:H-01\x00",
    "stage5:100%",
    "stage5:a b",
    "stage5:é",
    "stage5:-leading-dash",
    "stage5:.",
]


@pytest.mark.parametrize("task_key", HOSTILE_KEYS)
def test_every_tracked_key_round_trips_and_stays_in_markers_dir(
    tmp_path: Path, task_key: str
) -> None:
    checkpoint = _checkpoint(tmp_path)

    name = _marker_name(checkpoint, task_key)

    assert name is not None
    assert "/" not in name and "\\" not in name and "\x00" not in name
    assert _decode_marker_name(name) == task_key
    assert _encode_task_key(task_key) == name


def test_distinct_task_keys_never_share_a_marker(tmp_path: Path) -> None:
    checkpoint = _checkpoint(tmp_path)

    names = [_marker_name(checkpoint, key) for key in HOSTILE_KEYS]

    assert all(name is not None for name in names)
    assert len(set(names)) == len(HOSTILE_KEYS)


def test_colon_in_suffix_no_longer_shares_another_task_marker(tmp_path: Path) -> None:
    """Regression: ``stage5:H-1:2`` used to encode to ``stage5-H-1-2``.

    That is the marker of the unrelated ``stage5:H-1-2`` task, so either task
    could be skipped as "already complete" or have its marker cleared by the
    other. Each key now owns its marker.
    """
    checkpoint = _checkpoint(tmp_path)

    assert _marker_name(checkpoint, "stage5:H-1:2") != _marker_name(
        checkpoint, "stage5:H-1-2"
    )

    checkpoint.mark_complete("stage5:H-1-2")
    assert checkpoint.is_complete("stage5:H-1-2")
    assert not checkpoint.is_complete("stage5:H-1:2")

    checkpoint.mark_complete("stage5:H-1:2")
    checkpoint.clear("stage5:H-1:2")
    assert checkpoint.is_complete("stage5:H-1-2")
    assert not checkpoint.is_complete("stage5:H-1:2")


def test_legacy_markers_still_resume_in_flight_runs(tmp_path: Path) -> None:
    markers = tmp_path / ".markers"
    markers.mkdir()
    legacy = markers / "stage5-H-01"
    legacy.touch()
    checkpoint = _checkpoint(tmp_path)

    assert checkpoint.is_complete("stage5:H-01")

    # New completions use the reversible name; clearing retires the legacy one
    # so a stale marker cannot keep reporting the task complete.
    checkpoint.clear("stage5:H-01")
    assert not legacy.exists()
    checkpoint.mark_complete("stage5:H-01")
    assert (markers / "stage5--H-01").exists()
    assert not legacy.exists()


def test_ambiguous_keys_do_not_borrow_a_legacy_marker(tmp_path: Path) -> None:
    markers = tmp_path / ".markers"
    markers.mkdir()
    (markers / "stage5-H-1-2").touch()
    checkpoint = _checkpoint(tmp_path)

    # ``stage5:H-1-2`` is the key the old encoding represented unambiguously.
    assert checkpoint.is_complete("stage5:H-1-2")
    # ``stage5:H-1:2`` could never be told apart from it by the old name, so it
    # must re-run instead of inheriting that evidence.
    assert not checkpoint.is_complete("stage5:H-1:2")
    assert _legacy_marker_name("stage5:H-1:2") is None
    # A legacy name is never the new-style name of another key.
    assert _legacy_marker_name("stage5:-x") is None
    assert _decode_marker_name("stage5--x") == "stage5:x"


def test_hostile_keys_write_only_inside_the_markers_dir(tmp_path: Path) -> None:
    checkpoint = _checkpoint(tmp_path)

    for key in ("stage5:../../escape", "stage3:AU/1", "stage5:H-01\x00"):
        checkpoint.mark_complete(key)
        assert checkpoint.is_complete(key)

    markers = tmp_path / ".markers"
    written = sorted(path.name for path in markers.iterdir())
    assert written
    assert all("/" not in name and "\x00" not in name for name in written)
    # Nothing was written outside ``.markers/``.
    assert sorted(p.name for p in tmp_path.iterdir()) == [".markers"]


def test_overlong_and_malformed_keys_are_untracked(tmp_path: Path) -> None:
    checkpoint = _checkpoint(tmp_path)

    for key in ("stage5:" + "A" * 300, "stage5-extra", "stage123:x", "nonsense", ""):
        assert checkpoint._marker_path(key) is None
        checkpoint.mark_complete(key)  # must not raise
        assert not checkpoint.is_complete(key)
        checkpoint.clear(key)  # must not raise

    markers = tmp_path / ".markers"
    assert not markers.exists() or list(markers.iterdir()) == []


def test_stage4_pending_fallback_never_escapes_pending_dir(tmp_path: Path) -> None:
    checkpoint = _checkpoint(tmp_path)
    escape = tmp_path / "stage4-vulnerabilities" / "AU-1-F-1.json"
    escape.parent.mkdir(parents=True)
    escape.write_text("{}", encoding="utf-8")

    # Pre-fix this joined ``_pending/../AU-1-F-1.json`` and reported complete.
    assert not checkpoint.is_complete("stage4:../AU-1-F-1.json")

    pending = tmp_path / "stage4-vulnerabilities" / "_pending" / "AU-1-F-1.json"
    pending.parent.mkdir(parents=True, exist_ok=True)
    pending.write_text("{}", encoding="utf-8")
    assert checkpoint.is_complete("stage4:AU-1-F-1.json")


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("stage2", "stage2"),
        ("stage5--H-01", "stage5:H-01"),
        ("stage5--H-1%3A2", "stage5:H-1:2"),
        ("stage5--a%20b", "stage5:a b"),
        ("stage5-H-01", None),  # legacy, not produced by this scheme
        ("stage5", "stage5"),
        ("stage123--x", None),
        ("nonsense", None),
    ],
)
def test_decode_marker_name_is_the_inverse(name: str, expected: str | None) -> None:
    assert _decode_marker_name(name) == expected


def test_stage5_ignores_stage4_findings_with_unusable_ids(tmp_path: Path) -> None:
    findings = tmp_path / "stage4-vulnerabilities"
    findings.mkdir(parents=True)

    def write_finding(name: str, payload: object) -> Path:
        path = findings / name
        path.write_text(json.dumps(payload), encoding="utf-8")
        return path

    assert stage5._read_vuln_id(str(write_finding("H-01.json", {"id": "H-01"}))) == "H-01"
    assert stage5._read_vuln_id(str(write_finding("H-1:2.json", {"id": "H-1:2"}))) is None
    assert stage5._read_vuln_id(str(write_finding("H-02.json", {"id": "../H-02"}))) is None
    assert stage5._read_vuln_id(str(write_finding("H-03.json", {"id": 7}))) is None
    assert stage5._read_vuln_id(str(write_finding("H-04.json", []))) is None


def test_stage6_rejects_false_positive_and_malformed_poc_dirs() -> None:
    assert stage6._vuln_id_from_report("/out/stage5-pocs/H-01/report.md") == "H-01"
    assert stage6._vuln_id_from_report("/out/stage5-pocs/H-01_fp/report.md") is None
    assert stage6._vuln_id_from_report("/out/stage5-pocs/H-1:2/report.md") is None
    assert stage6._vuln_id_from_report("/out/stage5-pocs/1H-01/report.md") is None
    assert stage6._vuln_id_from_report("/out/stage5-pocs/evil:dir/report.md") is None


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("H-01", "H-01"),
        ("AU-1-F-1", "AU-1-F-1"),
        ("H_01", "H_01"),
        ("H-1:2", None),
        ("../H-01", None),
        ("1H-01", None),
        ("", None),
        ("H" * 65, None),
        (None, None),
        (7, None),
    ],
)
def test_validate_vuln_id_shared_grammar(value: object, expected: str | None) -> None:
    assert validate_vuln_id(value) == expected
