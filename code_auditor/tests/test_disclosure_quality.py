from __future__ import annotations

import zipfile
from pathlib import Path

import pytest

from code_auditor.cvss import base_score, report_score_errors
from code_auditor.validation.stage6 import validate_stage6_disclosure


@pytest.mark.parametrize(
    ("vector", "expected"),
    [
        ("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
        ("AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", 8.1),
        ("AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H", 9.6),
        ("AV:L/AC:L/PR:H/UI:N/S:C/C:N/I:N/A:H", 6.0),
        ("AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0),
        ("CVSS:3.1/S:C/AV:L/AC:L/PR:H/UI:N/C:N/I:N/A:H", 6.0),
    ],
)
def test_cvss_base_equations(vector: str, expected: float) -> None:
    assert base_score(vector) == expected


@pytest.mark.parametrize(
    "vector",
    [
        "AV:N/AC:L/PR:N/UI:N/C:H/I:H/A:H",
        "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/S:C",
        "AV:N/AC:L/PR:N/UI:N/S:Q/C:H/I:H/A:H",
    ],
)
def test_cvss_rejects_missing_duplicate_or_invalid_metrics(vector: str) -> None:
    with pytest.raises(ValueError):
        base_score(vector)


def test_cvss_checks_wrapped_score_and_reordered_vector() -> None:
    text = "CVSS v3.1: 8.1 High\n\nVector: CVSS:3.1/S:U/AV:N/AC:L/PR:N/UI:N/C:H/I:H/A:H"
    assert "9.8" in report_score_errors(text)[0]
    assert report_score_errors(text.replace("8.1", "9.8")) == []


def _package(base: Path, *, report: str | None = None) -> None:
    text = report or (
        "# Example report\n\n## Summary\nExample.\n\n"
        "## Why This Is a Security Issue\nBoundary explanation.\n\n"
        "## Severity Assessment\nCVSS v3.1: 7.5 High\n"
        "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H\n\n"
        "## Security Impact\nAvailability.\n\n## Root Cause\nExample.\n\n"
        "## Reproduction\n### Observed Result\nRetained example evidence.\n"
    )
    (base / "report.md").write_text(text)
    (base / "email.txt").write_text("Subject: Example\n continuation\n\nBody.\n")
    (base / "evidence.txt").write_text("Benign fixture\n")
    with zipfile.ZipFile(base / "disclosure.zip", "w") as archive:
        for name in ("report.md", "evidence.txt"):
            archive.write(base / name, name)


def _errors(base: Path) -> list[str]:
    return [i.description for i in validate_stage6_disclosure(str(base))]


def test_static_package_validation_accepts_consistent_documents(tmp_path: Path) -> None:
    _package(tmp_path)
    assert _errors(tmp_path) == []


def test_github_template_is_preserved(tmp_path: Path) -> None:
    _package(
        tmp_path,
        report="### Summary\nOne.\n### Details\nTwo.\n### PoC\nExisting evidence.\n### Impact\nFour.\n",
    )
    assert _errors(tmp_path) == []


def test_section_names_inside_code_do_not_satisfy_template(tmp_path: Path) -> None:
    _package(tmp_path, report="# Report\n```markdown\n## Summary\nExample\n```\n")
    assert any(
        "Missing required section" in x and "Summary" in x for x in _errors(tmp_path)
    )


def test_empty_section_fails(tmp_path: Path) -> None:
    _package(
        tmp_path,
        report="### Summary\n### Details\nTwo.\n### PoC\nThree.\n### Impact\nFour.\n",
    )
    assert "Empty required section in disclosure report: Summary" in _errors(tmp_path)


def test_same_size_changed_archive_file_fails(tmp_path: Path) -> None:
    _package(tmp_path)
    evidence = tmp_path / "evidence.txt"
    evidence.write_text(evidence.read_text().replace("Benign", "Edited"))
    assert "Archive and local file differ: evidence.txt" in _errors(tmp_path)


def test_archive_only_support_file_is_valid(tmp_path: Path) -> None:
    _package(tmp_path)
    (tmp_path / "evidence.txt").unlink()
    assert _errors(tmp_path) == []


def test_corrupt_archive_is_diagnostic(tmp_path: Path) -> None:
    _package(tmp_path)
    (tmp_path / "disclosure.zip").write_bytes(b"broken")
    assert any("corrupt disclosure archive" in x for x in _errors(tmp_path))


@pytest.mark.parametrize(
    ("target", "valid"), [("evidence.txt", True), ("../outside", False)]
)
def test_archive_symlink_must_stay_inside_package(
    tmp_path: Path, target: str, valid: bool
) -> None:
    _package(tmp_path)
    with zipfile.ZipFile(tmp_path / "disclosure.zip", "a") as archive:
        member = zipfile.ZipInfo("support-link")
        member.create_system = 3
        member.external_attr = 0o120777 << 16
        archive.writestr(member, target)
    assert bool(_errors(tmp_path)) is not valid


@pytest.mark.parametrize(
    "email",
    [
        "Subject: Example\nBody without separator\n",
        "Subject: Example\nunindented continuation\n\nBody\n",
    ],
)
def test_malformed_email_headers_fail(tmp_path: Path, email: str) -> None:
    _package(tmp_path)
    (tmp_path / "email.txt").write_text(email)
    assert any("email" in x for x in _errors(tmp_path))
