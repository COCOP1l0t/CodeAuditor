from __future__ import annotations

from code_auditor.reproduction_status import _find_status_value, read_reproduction_status


def test_broader_negation_phrasings_are_not_reproduced() -> None:
    cases = [
        "Reproduction Status: cannot be reproduced",
        "The crash was not fully reproduced",
        "It has not been reproduced on this revision",
        "The issue is no longer reproduced",
        "The bug is not currently reproduced",
        "cannot reproduce the failure",
    ]
    for text in cases:
        assert _find_status_value(text) == "not-reproduced", text


def test_affirmative_status_still_wins_over_incidental_negation() -> None:
    assert (
        _find_status_value(
            "reproduced (the first attempt failed to reproduce the crash, "
            "the second succeeded)"
        )
        == "reproduced"
    )
    assert _find_status_value("The vulnerability was successfully reproduced") == "reproduced"


def test_normalize_collapses_separator_run() -> None:
    # "partially - reproduced" must normalize to the canonical hyphenated form.
    assert _find_status_value("partially - reproduced") == "partially-reproduced"


def test_read_reproduction_status_handles_negated_report(tmp_path) -> None:
    report = tmp_path / "report.md"
    report.write_text(
        "# Finding\n\n## Reproduction Status\n\nThe crash cannot be reproduced "
        "on the pinned revision.\n",
        encoding="utf-8",
    )
    assert read_reproduction_status(str(report)) == "not-reproduced"
