from __future__ import annotations

import json

from ..config import ValidationIssue
from .common import read_file_or_issues


def validate_stage1_file(file_path: str) -> list[ValidationIssue]:
    content, issues = read_file_or_issues(file_path)
    if issues:
        return issues

    if not content.strip():
        return [ValidationIssue(
            description="Output file is empty.",
            expected="A JSON research record with project metadata and security findings.",
            fix="Write the Stage 1 research record as JSON to this file.",
        )]

    try:
        data = json.loads(content)
    except json.JSONDecodeError as e:
        return [ValidationIssue(
            description=f"Invalid JSON: {e}",
            expected="Valid JSON.",
            fix="Fix the JSON syntax error (trailing commas, missing quotes, etc.).",
        )]

    if not isinstance(data, dict):
        return [ValidationIssue(
            description="Output file root must be a JSON object.",
            expected="A JSON research record with project metadata and security findings.",
            fix="Rewrite the file as a single JSON object.",
        )]

    validation_issues: list[ValidationIssue] = []

    if "project" not in data:
        validation_issues.append(ValidationIssue(
            description='Missing required key: "project".',
            expected='A "project" object with project metadata.',
            fix='Add a "project" object with "name", "path", "language", "description" fields.',
        ))

    return validation_issues
