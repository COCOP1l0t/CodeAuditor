from __future__ import annotations

from code_auditor.stages import stage6


def test_report_title_ignores_headings_inside_fences(tmp_path) -> None:
    report = tmp_path / "report.md"
    report.write_text(
        "```sh\n# not the title\nmake\n```\n\n# Real Disclosure Title\n",
        encoding="utf-8",
    )
    assert stage6._extract_report_title(str(report)) == "Real Disclosure Title"


def test_report_section_keeps_fenced_hash_lines(tmp_path) -> None:
    content = (
        "## Summary\n\nA heap overflow.\n\n"
        "## Reproduction\n\nBuild the target:\n\n"
        "```sh\n# build the target\nmake\n```\n\n"
        "Then run the PoC.\n\n"
        "## Impact\n\nRemote code execution.\n"
    )
    section = stage6._extract_report_section(content, "Reproduction")
    assert section is not None
    assert "# build the target" in section
    assert "Then run the PoC." in section
    # The following section must not leak into the reproduction body.
    assert "Remote code execution." not in section
