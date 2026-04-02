from __future__ import annotations

import json
import os
import re

from ..config import ValidationIssue

_PLACEHOLDERS = {"none", "n/a", "...", "tbd", ""}


def _is_blank(value: object) -> bool:
    if isinstance(value, str):
        return value.lower().strip() in _PLACEHOLDERS
    if isinstance(value, list):
        return len(value) == 0
    return not value


def validate_stage2_dir(result_dir: str) -> list[ValidationIssue]:
    """Validate the directory of AU-*.json files produced by stage 2."""
    issues: list[ValidationIssue] = []

    if not os.path.isdir(result_dir):
        return [ValidationIssue(
            description=f"Result directory does not exist: {result_dir}",
            expected="A directory containing AU-*.json files.",
            fix="Ensure stage 2 wrote output to the correct directory.",
        )]

    pattern = re.compile(r"^AU-(\d+)\.json$")
    au_files = sorted(
        (name for name in os.listdir(result_dir) if pattern.match(name)),
        key=lambda n: int(pattern.match(n).group(1)),  # type: ignore[union-attr]
    )

    if not au_files:
        return [ValidationIssue(
            description="No AU-*.json files found in result directory.",
            expected="At least one AU-{N}.json file.",
            fix="Write analysis unit files as AU-1.json, AU-2.json, etc.",
        )]

    # Check sequential IDs
    for expected_num, name in enumerate(au_files, start=1):
        m = pattern.match(name)
        actual_num = int(m.group(1))  # type: ignore[union-attr]
        if actual_num != expected_num:
            issues.append(ValidationIssue(
                description=f"Non-sequential AU ID: expected AU-{expected_num}, found {name}.",
                expected="AU IDs must be sequential: AU-1, AU-2, AU-3, ...",
                fix=f"Rename {name} to AU-{expected_num}.json.",
            ))

    # Validate each file
    analyze_count = 0
    for name in au_files:
        file_path = os.path.join(result_dir, name)
        file_issues = validate_stage2_au_file(file_path)
        issues.extend(file_issues)

        # Count analyze: true
        try:
            with open(file_path) as f:
                data = json.load(f)
            if data.get("analyze", True):
                analyze_count += 1
        except (json.JSONDecodeError, OSError):
            pass

    if analyze_count > 50:
        issues.append(ValidationIssue(
            description=f"Too many units selected for analysis: {analyze_count} (max 50).",
            expected="At most 50 units with analyze: true.",
            fix="Set analyze to false for lower-priority units.",
        ))

    return issues


def validate_stage2_au_file(file_path: str) -> list[ValidationIssue]:
    """Validate a single AU-*.json file."""
    name = os.path.basename(file_path)
    issues: list[ValidationIssue] = []

    try:
        with open(file_path) as f:
            content = f.read()
    except FileNotFoundError:
        return [ValidationIssue(
            description=f"File not found: {file_path}",
            expected="The AU file should exist.",
            fix="Ensure the file was written.",
        )]

    if not content.strip():
        return [ValidationIssue(
            description=f"{name}: file is empty.",
            expected="A JSON object with description, files, focus, and analyze fields.",
            fix="Write the analysis unit definition as JSON.",
        )]

    try:
        data = json.loads(content)
    except json.JSONDecodeError as e:
        return [ValidationIssue(
            description=f"{name}: invalid JSON: {e}",
            expected="Valid JSON.",
            fix="Fix the JSON syntax error.",
        )]

    if _is_blank(data.get("description")):
        issues.append(ValidationIssue(
            description=f'{name}: missing or blank "description".',
            expected="A short description of what this unit covers.",
            fix='Add a "description" field.',
        ))
    if _is_blank(data.get("files")):
        issues.append(ValidationIssue(
            description=f'{name}: missing or empty "files".',
            expected="A non-empty array of source file paths.",
            fix='Add a "files" array with at least one path.',
        ))
    if _is_blank(data.get("focus")):
        issues.append(ValidationIssue(
            description=f'{name}: missing or blank "focus".',
            expected="Concrete analysis guidance.",
            fix='Add a "focus" field with actionable analysis guidance.',
        ))
    if "analyze" not in data or not isinstance(data["analyze"], bool):
        issues.append(ValidationIssue(
            description=f'{name}: missing or non-boolean "analyze".',
            expected='A boolean "analyze" field (true or false).',
            fix='Add "analyze": true or "analyze": false.',
        ))

    return issues
