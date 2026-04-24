from __future__ import annotations

from ..config import ValidationIssue
from .common import read_file_or_issues


_REQUIRED_SECTIONS = [
    "Verdict",
    "Summary",
    "PoC Behavior",
    "Documentation References",
    "Analysis",
    "Justification",
]

_VALID_VERDICTS = ("real-vulnerability", "api-misuse", "uncertain")


def validate_stage6_verdict(verdict_path: str) -> list[ValidationIssue]:
    """Validate a Stage 6 API-misuse verdict.md file."""
    content, issues = read_file_or_issues(verdict_path)
    if issues:
        return issues

    lower = content.lower()

    for section in _REQUIRED_SECTIONS:
        if f"## {section}".lower() not in lower:
            issues.append(ValidationIssue(
                description=f"Missing required section: {section}",
                expected=f"verdict.md must contain a '## {section}' section.",
                fix=f"Add a '## {section}' section to {verdict_path}.",
            ))

    if not any(v in lower for v in _VALID_VERDICTS):
        issues.append(ValidationIssue(
            description="Missing or invalid verdict value",
            expected=f"verdict.md must state one of: {', '.join(_VALID_VERDICTS)}",
            fix="State `real-vulnerability`, `api-misuse`, or `uncertain` in the Verdict section.",
        ))

    return issues
