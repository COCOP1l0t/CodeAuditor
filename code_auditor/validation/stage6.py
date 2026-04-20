from __future__ import annotations

from ..config import ValidationIssue
from .common import file_missing_issue, read_file_or_issues


_REQUIRED_SECTIONS = [
    "Title",
    "Summary",
    "Reproduction Status",
]


def validate_stage6_report(path: str) -> list[ValidationIssue]:
    """Validate a Stage 6 PoC report.md file."""
    if not path:
        return [file_missing_issue("stage6 report")]

    content, issues = read_file_or_issues(path)
    if issues:
        return issues

    for section in _REQUIRED_SECTIONS:
        if section.lower() not in content.lower():
            issues.append(ValidationIssue(
                description=f"Missing required section: {section}",
                expected=f"Report must contain a '{section}' section.",
                fix=f"Add a '## {section}' or '**{section}**' section to the report.",
            ))

    valid_statuses = ["reproduced", "partially-reproduced", "not-reproduced", "false-positive"]
    status_found = any(s in content.lower() for s in valid_statuses)
    if not status_found:
        issues.append(ValidationIssue(
            description="Missing reproduction status value",
            expected=f"Report must contain one of: {', '.join(valid_statuses)}",
            fix="Add a Reproduction Status section with one of the valid status values.",
        ))

    return issues
