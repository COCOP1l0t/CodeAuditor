from __future__ import annotations

import os

from ..config import ValidationIssue
from ..poc_artifacts import TRIGGER_GRAPH_FILENAME, load_trigger_graph
from .common import file_missing_issue, read_file_or_issues


_REQUIRED_SECTIONS = [
    "Title",
    "Summary",
    "Reproduction Status",
]


def validate_stage5_report(path: str) -> list[ValidationIssue]:
    """Validate a Stage 5 PoC report.md file."""
    if not path:
        return [file_missing_issue("stage5 report")]

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


def validate_stage5_trigger_graph(
    poc_dir: str,
    finding_id: str,
) -> list[ValidationIssue]:
    """Validate the interactive PoC trigger graph produced by Stage 5."""
    graph_path = os.path.join(poc_dir, TRIGGER_GRAPH_FILENAME)
    _, errors = load_trigger_graph(
        graph_path,
        expected_finding_id=finding_id,
    )
    return [
        ValidationIssue(
            description=error,
            expected=(
                f"{TRIGGER_GRAPH_FILENAME} must describe a bounded, evidence-backed "
                "call path from attacker-controlled source to vulnerability sink."
            ),
            fix=f"Correct {graph_path} without inventing runtime evidence.",
        )
        for error in errors
    ]
