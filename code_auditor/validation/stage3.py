from __future__ import annotations

import json

from ..config import ValidationIssue
from .common import read_file_or_issues

_REQUIRED_KEYS = ["finding_id", "title", "location", "vulnerability_class", "root_cause", "preliminary_severity"]
_VALID_SEVERITIES = {"critical", "high", "medium", "low"}


def validate_stage3_file(file_path: str) -> list[ValidationIssue]:
    content, issues = read_file_or_issues(file_path)
    if issues:
        return issues

    if not content.strip():
        return [ValidationIssue(
            description="Bug finding file is empty.",
            expected="A JSON object with finding details.",
            fix="Write the finding as JSON, or delete the file if no bugs were found.",
        )]

    try:
        data = json.loads(content)
    except json.JSONDecodeError as e:
        return [ValidationIssue(
            description=f"Invalid JSON: {e}",
            expected="Valid JSON.",
            fix="Fix the JSON syntax error.",
        )]

    validation_issues: list[ValidationIssue] = []

    for key in _REQUIRED_KEYS:
        if key not in data or not data[key]:
            validation_issues.append(ValidationIssue(
                description=f'Missing required key: "{key}".',
                expected=f'A non-empty "{key}" field.',
                fix=f'Add "{key}" to the JSON object.',
            ))

    severity = data.get("preliminary_severity", "")
    if isinstance(severity, str) and severity and severity.lower() not in _VALID_SEVERITIES:
        validation_issues.append(ValidationIssue(
            description=f'Invalid preliminary_severity: "{severity}".',
            expected="One of: Critical, High, Medium, Low.",
            fix="Change preliminary_severity to one of: Critical, High, Medium, Low.",
        ))

    return validation_issues
