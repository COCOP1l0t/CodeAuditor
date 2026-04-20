from __future__ import annotations

import json
import os
import re

from ..config import ValidationIssue

_PLACEHOLDERS = {"none", "n/a", "...", "tbd", ""}

DEFAULT_MAX_ANALYSIS_UNITS = 30


def _is_blank(value: object) -> bool:
    if isinstance(value, str):
        return value.lower().strip() in _PLACEHOLDERS
    if isinstance(value, list):
        return len(value) == 0
    return not value


def validate_stage3_dir(result_dir: str, max_aus: int = DEFAULT_MAX_ANALYSIS_UNITS) -> list[ValidationIssue]:
    """Validate the directory of AU-*.json files and triage.json produced by stage 3."""
    issues: list[ValidationIssue] = []

    if not os.path.isdir(result_dir):
        return [ValidationIssue(
            description=f"Result directory does not exist: {result_dir}",
            expected="A directory containing triage.json and AU-*.json files.",
            fix="Ensure stage 3 wrote output to the correct directory.",
        )]

    # Validate triage.json
    issues.extend(validate_triage_file(os.path.join(result_dir, "triage.json"), max_aus=max_aus))

    # Collect AU files
    pattern = re.compile(r"^AU-(\d+)\.json$")
    au_files = sorted(
        (name for name in os.listdir(result_dir) if pattern.match(name)),
        key=lambda n: int(pattern.match(n).group(1)),  # type: ignore[union-attr]
    )

    if not au_files:
        return issues + [ValidationIssue(
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

    # Check total AU count (allow up to 50% over the target before flagging)
    hard_limit = max_aus + max_aus // 2
    if len(au_files) > hard_limit:
        issues.append(ValidationIssue(
            description=f"Too many analysis units: {len(au_files)} (target {max_aus}, hard limit {hard_limit}).",
            expected=f"At most {hard_limit} analysis unit files (target: {max_aus}).",
            fix="Reduce the number of analysis units by being more selective in the triage step.",
        ))

    # Validate each AU file
    for name in au_files:
        file_path = os.path.join(result_dir, name)
        issues.extend(validate_stage3_au_file(file_path))

    return issues


def validate_stage3_au_file(file_path: str) -> list[ValidationIssue]:
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
            expected="A JSON object with description, files, and focus fields.",
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

    return issues


def validate_triage_file(file_path: str, max_aus: int = DEFAULT_MAX_ANALYSIS_UNITS) -> list[ValidationIssue]:
    """Validate the triage.json manifest."""
    issues: list[ValidationIssue] = []

    try:
        with open(file_path) as f:
            content = f.read()
    except FileNotFoundError:
        return [ValidationIssue(
            description="triage.json not found.",
            expected="A triage manifest at triage.json in the result directory.",
            fix="Write the triage manifest before creating AU files.",
        )]

    if not content.strip():
        return [ValidationIssue(
            description="triage.json is empty.",
            expected="A JSON array of triage entries.",
            fix="Write the triage manifest as a JSON array.",
        )]

    try:
        data = json.loads(content)
    except json.JSONDecodeError as e:
        return [ValidationIssue(
            description=f"triage.json: invalid JSON: {e}",
            expected="Valid JSON.",
            fix="Fix the JSON syntax error.",
        )]

    if not isinstance(data, list):
        return [ValidationIssue(
            description="triage.json: root element is not an array.",
            expected="A JSON array of triage entries.",
            fix="Wrap the triage entries in a JSON array.",
        )]

    if len(data) == 0:
        issues.append(ValidationIssue(
            description="triage.json: empty array.",
            expected="At least one triage entry.",
            fix="Add triage entries for the project's functional areas.",
        ))

    selected_count = 0
    for i, entry in enumerate(data):
        if not isinstance(entry, dict):
            issues.append(ValidationIssue(
                description=f"triage.json[{i}]: entry is not an object.",
                expected="Each triage entry must be a JSON object.",
                fix=f"Fix entry at index {i}.",
            ))
            continue

        for field in ("area", "rationale"):
            if _is_blank(entry.get(field)):
                issues.append(ValidationIssue(
                    description=f'triage.json[{i}]: missing or blank "{field}".',
                    expected=f'A non-empty "{field}" field.',
                    fix=f'Add a "{field}" field to entry {i}.',
                ))

        if _is_blank(entry.get("files")):
            issues.append(ValidationIssue(
                description=f'triage.json[{i}]: missing or empty "files".',
                expected="A non-empty array of file paths.",
                fix=f'Add a "files" array to entry {i}.',
            ))

        if "selected" not in entry or not isinstance(entry["selected"], bool):
            issues.append(ValidationIssue(
                description=f'triage.json[{i}]: missing or non-boolean "selected".',
                expected='A boolean "selected" field (true or false).',
                fix=f'Add "selected": true or "selected": false to entry {i}.',
            ))
        elif entry["selected"]:
            selected_count += 1

    hard_limit = max_aus + max_aus // 2
    if selected_count > hard_limit:
        issues.append(ValidationIssue(
            description=f"triage.json: too many areas selected: {selected_count} (target {max_aus}, hard limit {hard_limit}).",
            expected=f"At most {hard_limit} areas with selected: true (target: {max_aus}).",
            fix="Reduce selected areas by being more selective.",
        ))

    return issues
