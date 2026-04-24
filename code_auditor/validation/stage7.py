from __future__ import annotations

import os

from ..config import ValidationIssue
from .common import read_file_or_issues


_REQUIRED_REPORT_SECTIONS = [
    "Summary",
    "Severity Assessment",
    "Security Impact",
    "Root Cause",
    "Reproduction",
]


def validate_stage7_disclosure(disclosure_dir: str) -> list[ValidationIssue]:
    """Validate Stage 7 disclosure artifacts."""
    issues: list[ValidationIssue] = []

    report_path = os.path.join(disclosure_dir, "report.md")
    email_path = os.path.join(disclosure_dir, "email.txt")
    zip_path = os.path.join(disclosure_dir, "disclosure.zip")

    for path, name in [
        (report_path, "report.md"),
        (email_path, "email.txt"),
        (zip_path, "disclosure.zip"),
    ]:
        if not os.path.exists(path):
            issues.append(ValidationIssue(
                description=f"Missing required disclosure artifact: {name}",
                expected=f"'{name}' should exist in the disclosure directory.",
                fix=f"Create '{name}' in {disclosure_dir}.",
            ))

    # Validate report content
    if os.path.exists(report_path):
        content, read_issues = read_file_or_issues(report_path)
        if read_issues:
            issues.extend(read_issues)
        else:
            for section in _REQUIRED_REPORT_SECTIONS:
                if section.lower() not in content.lower():
                    issues.append(ValidationIssue(
                        description=f"Missing required section in disclosure report: {section}",
                        expected=f"Disclosure report must contain a '{section}' section.",
                        fix=f"Add a '{section}' section to disclosure/report.md.",
                    ))

    # Validate email content
    if os.path.exists(email_path):
        content, read_issues = read_file_or_issues(email_path)
        if read_issues:
            issues.extend(read_issues)
        elif "subject:" not in content.lower():
            issues.append(ValidationIssue(
                description="Missing Subject line in disclosure email",
                expected="Email must contain a 'Subject:' line.",
                fix="Add a 'Subject: [Security] ...' line at the top of email.txt.",
            ))

    return issues
