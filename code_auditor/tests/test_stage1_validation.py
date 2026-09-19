from __future__ import annotations

import json

from code_auditor.validation.stage1 import validate_stage1_outputs

_RECORD = {"project": {"name": "demo", "language": "c"}}
_FOCUS = (
    "# Auditing Focus\n\n"
    "## Explicit In-Scope and Out-of-Scope Modules\n\nIn scope: parser.\n\n"
    "## Historical Hot Spots\n\n- overflow in parser\n"
)
_CRITERIA = (
    "# Vulnerability Criteria\n\n"
    "## Explicit In-Scope and Out-of-Scope Issue Types\n\n"
    "In scope: memory corruption.\n"
)


def _write(tmp_path, record=_RECORD, focus=_FOCUS, criteria=_CRITERIA):
    record_path = tmp_path / "stage-1-security-context.json"
    focus_path = tmp_path / "auditing-focus.md"
    criteria_path = tmp_path / "vulnerability-criteria.md"
    if record is not None:
        record_path.write_text(json.dumps(record), encoding="utf-8")
    if focus is not None:
        focus_path.write_text(focus, encoding="utf-8")
    if criteria is not None:
        criteria_path.write_text(criteria, encoding="utf-8")
    return str(record_path), str(focus_path), str(criteria_path)


def test_valid_stage1_outputs_pass(tmp_path) -> None:
    assert validate_stage1_outputs(*_write(tmp_path)) == []


def test_missing_directive_is_reported(tmp_path) -> None:
    issues = validate_stage1_outputs(*_write(tmp_path, focus=None))
    assert any("auditing-focus.md" in issue.description for issue in issues)


def test_empty_directive_is_reported(tmp_path) -> None:
    issues = validate_stage1_outputs(*_write(tmp_path, criteria="   \n"))
    assert any("empty" in issue.description for issue in issues)


def test_directive_missing_section_is_reported(tmp_path) -> None:
    broken = "# Auditing Focus\n\nNothing parsed by Stage 2 here.\n"
    issues = validate_stage1_outputs(*_write(tmp_path, focus=broken))
    assert any("Historical Hot Spots" in issue.description for issue in issues)


def test_invalid_record_is_reported(tmp_path) -> None:
    issues = validate_stage1_outputs(*_write(tmp_path, record={"title": "no project"}))
    assert any('"project"' in issue.description for issue in issues)
