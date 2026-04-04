from __future__ import annotations

import json

from ..config import ValidationIssue
from .common import read_file_or_issues

_REQUIRED_KEYS = ["id", "title", "location", "data_flow_trace", "cwe_id", "vulnerability_class", "cvss_score"]

_DATA_FLOW_TRACE_KEYS = ["entry_point", "propagation_chain", "neutralizing_checks", "sink"]


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

    validation_issues: list[ValidationIssue] = []

    for key in _REQUIRED_KEYS:
        if key not in data:
            validation_issues.append(ValidationIssue(
                description=f'Missing required key: "{key}".',
                expected=f'The JSON object must contain "{key}".',
                fix=f'Add "{key}" to the JSON object.',
            ))

    trace = data.get("data_flow_trace")
    if trace is not None:
        if not isinstance(trace, dict):
            validation_issues.append(ValidationIssue(
                description='"data_flow_trace" must be a JSON object.',
                expected="A JSON object with keys: entry_point, propagation_chain, neutralizing_checks, sink.",
                fix='Set "data_flow_trace" to a JSON object with the required subfields.',
            ))
        else:
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

    cvss_raw = data.get("cvss_score")
    if cvss_raw is not None:
        try:
            cvss = float(cvss_raw)
            if not (0.0 <= cvss <= 10.0):
                validation_issues.append(ValidationIssue(
                    description=f'CVSS score out of range: {cvss}.',
                    expected="A number between 0.0 and 10.0.",
                    fix='Set "cvss_score" to a value between 0.0 and 10.0.',
                ))
        except (TypeError, ValueError):
            validation_issues.append(ValidationIssue(
                description=f'Invalid cvss_score: "{cvss_raw}".',
                expected="A numeric CVSS v3.1 base score (e.g. \"7.5\").",
                fix='Set "cvss_score" to a numeric string like "7.5".',
            ))

    return validation_issues
