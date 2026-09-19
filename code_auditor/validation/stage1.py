from __future__ import annotations

import json
import re

from ..config import ValidationIssue
from .common import read_file_or_issues

# Headings Stage 2 parses out of the two auditing directives; a directive that
# lost them silently degrades the focus/criteria injected into Stages 2-4.
_DIRECTIVE_SECTIONS = {
    "auditing-focus.md": (
        "## Explicit In-Scope and Out-of-Scope Modules",
        "## Historical Hot Spots",
    ),
    "vulnerability-criteria.md": (
        "## Explicit In-Scope and Out-of-Scope Issue Types",
    ),
}


def _heading_present(content: str, heading: str) -> bool:
    pattern = re.compile(rf"^\s*{re.escape(heading)}\s*$", re.MULTILINE)
    return pattern.search(content) is not None


def validate_stage1_directive(file_path: str, filename: str) -> list[ValidationIssue]:
    """Validate one auditing directive file exists, is non-empty, and has its sections."""
    content, issues = read_file_or_issues(file_path)
    if issues:
        return issues
    if not content.strip():
        return [
            ValidationIssue(
                description=f"{filename} is empty.",
                expected="A concise, actionable auditing directive.",
                fix=f"Write the {filename} directive with its required Markdown sections.",
            )
        ]
    missing = [
        heading
        for heading in _DIRECTIVE_SECTIONS.get(filename, ())
        if not _heading_present(content, heading)
    ]
    if missing:
        return [
            ValidationIssue(
                description=f"{filename} is missing required section(s): "
                + ", ".join(missing),
                expected="Every section the downstream stages parse must be present.",
                fix=f"Add the missing section heading(s) to {filename}.",
            )
        ]
    return []


def validate_stage1_outputs(
    research_record_path: str,
    auditing_focus_path: str,
    vuln_criteria_path: str,
) -> list[ValidationIssue]:
    """Validate all three Stage 1 outputs before the stage is checkpointed."""
    issues = list(validate_stage1_file(research_record_path))
    issues.extend(
        validate_stage1_directive(auditing_focus_path, "auditing-focus.md")
    )
    issues.extend(
        validate_stage1_directive(vuln_criteria_path, "vulnerability-criteria.md")
    )
    return issues


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
