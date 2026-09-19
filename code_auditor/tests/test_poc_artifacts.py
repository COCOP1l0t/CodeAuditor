from __future__ import annotations

from pathlib import Path

from code_auditor.poc_artifacts import (
    resolve_stage5_report_path,
    stage5_vuln_id,
)


def _write_report(output_dir: Path, poc_name: str) -> Path:
    report = output_dir / "stage5-pocs" / poc_name / "report.md"
    report.parent.mkdir(parents=True, exist_ok=True)
    report.write_text("# PoC\n", encoding="utf-8")
    return report


def test_resolve_accepts_retained_reproduced_report(tmp_path: Path) -> None:
    output_dir = tmp_path / "audit-output"
    _write_report(output_dir, "H-01")

    assert resolve_stage5_report_path(
        str(output_dir), "stage5-pocs/H-01/report.md"
    ) == str(output_dir / "stage5-pocs" / "H-01" / "report.md")


def test_resolve_rejects_false_positive_unless_requested(tmp_path: Path) -> None:
    output_dir = tmp_path / "audit-output"
    _write_report(output_dir, "L-02_fp")

    assert resolve_stage5_report_path(str(output_dir), "stage5-pocs/L-02_fp/report.md") is None
    assert resolve_stage5_report_path(
        str(output_dir),
        "stage5-pocs/L-02_fp/report.md",
        allow_false_positive=True,
    ) == str(output_dir / "stage5-pocs" / "L-02_fp" / "report.md")


def test_resolve_rejects_empty_root_instead_of_cwd(
    tmp_path: Path, monkeypatch
) -> None:
    """``realpath("")`` is the CWD, so an empty root must never resolve."""
    _write_report(tmp_path, "H-01")
    monkeypatch.chdir(tmp_path)

    assert resolve_stage5_report_path("", "stage5-pocs/H-01/report.md") is None
    assert resolve_stage5_report_path(None, "stage5-pocs/H-01/report.md") is None


def test_resolve_rejects_escape_and_bad_shapes(tmp_path: Path) -> None:
    output_dir = tmp_path / "audit-output"
    _write_report(output_dir, "H-01")
    outside = _write_report(tmp_path / "outside", "H-01")

    assert resolve_stage5_report_path(str(output_dir), str(outside)) is None
    assert resolve_stage5_report_path(str(output_dir), "../outside/stage5-pocs/H-01/report.md") is None
    assert resolve_stage5_report_path(str(output_dir), "stage5-pocs/H-01/notes.md") is None
    assert resolve_stage5_report_path(str(output_dir), "stage5-pocs/../H-01/report.md") is None
    assert resolve_stage5_report_path(str(output_dir), "") is None
    assert resolve_stage5_report_path(str(output_dir), "stage5-pocs/H-01/report.md\x00") is None


def test_resolve_rejects_missing_file(tmp_path: Path) -> None:
    output_dir = tmp_path / "audit-output"
    (output_dir / "stage5-pocs" / "H-01").mkdir(parents=True)

    assert resolve_stage5_report_path(str(output_dir), "stage5-pocs/H-01/report.md") is None


def test_stage5_vuln_id_rules() -> None:
    assert stage5_vuln_id("H-01") == "H-01"
    assert stage5_vuln_id("H-01_fp") is None
    assert stage5_vuln_id("H-01_fp", allow_false_positive=True) == "H-01"
    assert stage5_vuln_id("_fp", allow_false_positive=True) is None
    assert stage5_vuln_id("1H-01") is None
    assert stage5_vuln_id("H-01/evil") is None
    assert stage5_vuln_id("H" * 65) is None
