from __future__ import annotations

import re

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


def find_section(content: str, heading: str) -> str | None:
    escaped = re.escape(heading)
    pattern = re.compile(rf"(?:^|\n)##\s+{escaped}\s*\n([\s\S]*?)(?=\n## |$)")
    m = pattern.search(content)
    if m is None:
        return None
    return m.group(1).strip() or None


def parse_markdown_table_rows(section_text: str) -> list[list[str]]:
    table_lines = [line for line in section_text.split("\n") if line.strip().startswith("|")]
    if len(table_lines) < 2:
        return []
    # Skip header and separator rows
    return [
        [cell.strip() for cell in line.strip().strip("|").split("|")]
        for line in table_lines[2:]
    ]


def check_field(block_text: str, field_name: str) -> str | None:
    escaped = re.escape(field_name)
    pattern = re.compile(rf"\*\*{escaped}\*\*\s*:\s*(.+)")
    m = pattern.search(block_text)
    if m is None:
        return None
    return m.group(1).strip()
