from __future__ import annotations

from ..config import ValidationIssue


def file_missing_issue(file_path: str) -> ValidationIssue:
    return ValidationIssue(
        description=f'Output file not found: "{file_path}"',
        expected="The file should exist at the specified path.",
        fix="Ensure the output file was written to the correct path.",
    )


def read_file_or_issues(file_path: str) -> tuple[str, list[ValidationIssue]]:
    """Read an agent output file as text, never raising on bad bytes or I/O.

    Agent output has been observed with non-UTF-8 bytes (for example a stray
    binary byte inside a code snippet). Strict decoding would raise
    ``UnicodeDecodeError`` out of every validator and abort the audit, so the
    file is decoded with ``errors="replace"`` and all ``OSError`` variants are
    reported as validation issues instead of propagating.
    """
    try:
        with open(file_path, encoding="utf-8", errors="replace") as f:
            return f.read(), []
    except FileNotFoundError:
        return "", [file_missing_issue(file_path)]
    except OSError as exc:
        return "", [
            ValidationIssue(
                description=f'Cannot read output file "{file_path}": {exc}',
                expected="A readable output file at the specified path.",
                fix="Check that the path is a readable regular file.",
            )
        ]
