from __future__ import annotations

import json

from ..config import ValidationIssue
from .common import read_file_or_issues

_REQUIRED_KEYS = ["id", "title", "location", "data_flow_trace", "cwe_id", "vulnerability_class", "trigger", "cvss_score"]

_DATA_FLOW_TRACE_KEYS = ["entry_point", "propagation_chain", "neutralizing_checks", "sink"]


def _is_blank(value: object) -> bool:
    if value is None:
        return True
    if isinstance(value, str):
        return not value.strip()
    if isinstance(value, (list, dict, tuple, set)):
        return not value
    return False


def validate_stage4_file(file_path: str) -> list[ValidationIssue]:
    content, issues = read_file_or_issues(file_path)
    if issues:
        return issues

    if not content.strip():
        return [ValidationIssue(
            description="Output file is empty.",
            expected="A JSON object with evaluated finding details.",
            fix="Write the evaluated finding as a JSON object.",
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
            expected="A JSON object with evaluated finding details.",
            fix="Rewrite the file as a single JSON object.",
        )]

    validation_issues: list[ValidationIssue] = []

    for key in _REQUIRED_KEYS:
        if key not in data:
            validation_issues.append(ValidationIssue(
                description=f'Missing required key: "{key}".',
                expected=f'The JSON object must contain "{key}".',
                fix=f'Add "{key}" to the JSON object.',
            ))
        elif key != "cvss_score" and _is_blank(data[key]):
            # A present-but-empty value is not a real data flow / trigger / CWE
            # and would otherwise collapse distinct findings onto one dedupe key.
            validation_issues.append(ValidationIssue(
                description=f'Required key "{key}" must not be blank.',
                expected=f'A non-empty "{key}" value.',
                fix=f'Populate "{key}" with the evaluated finding data.',
            ))

    trace = data.get("data_flow_trace")
    if isinstance(trace, dict):
        for subkey in _DATA_FLOW_TRACE_KEYS:
            if subkey not in trace:
                validation_issues.append(ValidationIssue(
                    description=f'"data_flow_trace" is missing required key: "{subkey}".',
                    expected=f'"data_flow_trace" must contain "{subkey}".',
                    fix=f'Add "{subkey}" to the "data_flow_trace" object.',
                ))
        chain = trace.get("propagation_chain")
        if chain is not None and not isinstance(chain, list):
            validation_issues.append(ValidationIssue(
                description='"propagation_chain" must be a JSON array.',
                expected="A JSON array of strings describing each hop in the data flow.",
                fix='Set "propagation_chain" to a JSON array of strings.',
            ))
    elif not _is_blank(trace):
        validation_issues.append(ValidationIssue(
            description='"data_flow_trace" must be a JSON object.',
            expected="A JSON object with keys: entry_point, propagation_chain, neutralizing_checks, sink.",
            fix='Set "data_flow_trace" to a JSON object with the required subfields.',
        ))

    if "cvss_score" in data:
        cvss_raw = data["cvss_score"]
        if cvss_raw is None:
            validation_issues.append(ValidationIssue(
                description='"cvss_score" must be a numeric value.',
                expected="A CVSS v3.1 base score of at least 4.0.",
                fix='Set "cvss_score" to a value between 4.0 and 10.0.',
            ))
        else:
            try:
                cvss = float(cvss_raw)
            except (TypeError, ValueError):
                validation_issues.append(ValidationIssue(
                    description=f'Invalid cvss_score: "{cvss_raw}".',
                    expected="A numeric CVSS v3.1 base score (e.g. \"7.5\").",
                    fix='Set "cvss_score" to a numeric string like "7.5".',
                ))
            else:
                if not (0.0 <= cvss <= 10.0):
                    validation_issues.append(ValidationIssue(
                        description=f'CVSS score out of range: {cvss}.',
                        expected="A number between 0.0 and 10.0.",
                        fix='Set "cvss_score" to a value between 0.0 and 10.0.',
                    ))
                elif cvss < 4.0:
                    # The Stage 4 prompt writes output only for confirmed
                    # vulnerabilities at or above the disclosure threshold;
                    # enforce it so sub-threshold findings do not consume
                    # Stage 5/6 agent work.
                    validation_issues.append(ValidationIssue(
                        description=(
                            f"CVSS score {cvss:.1f} is below the 4.0 disclosure "
                            "threshold."
                        ),
                        expected="A confirmed vulnerability with CVSS >= 4.0.",
                        fix=(
                            "Do not emit an output file for a finding below CVSS "
                            "4.0; delete this file or raise the score if it is wrong."
                        ),
                    ))

    return validation_issues
