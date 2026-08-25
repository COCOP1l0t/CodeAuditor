from __future__ import annotations

from ..config import ValidationIssue


def file_missing_issue(file_path: str) -> ValidationIssue:
    return ValidationIssue(
        description=f'Output file not found: "{file_path}"',
        expected="The file should exist at the specified path.",
        fix="Ensure the output file was written to the correct path.",
    )


def read_file_or_issues(file_path: str) -> tuple[str, list[ValidationIssue]]:
    try:
        with open(file_path) as f:
            return f.read(), []
    except FileNotFoundError:
        return "", [file_missing_issue(file_path)]
