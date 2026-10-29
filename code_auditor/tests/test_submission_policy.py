from __future__ import annotations

import json
from pathlib import Path

from code_auditor.submission_policy import (
    detect_submission_policy,
    enforce_email_policy,
    write_submission_policy,
)


def test_detects_ai_report_prohibition_and_reporting_channels(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.mkdir()
    (target / "SECURITY.md").write_text(
        "# Security\n\n"
        "We do not accept AI generated security reports. Submitting one causes an automatic ban.\n\n"
        "Report at https://github.com/example/project/security/advisories/new\n"
        "Escalate to security@example.test after six business days.\n",
        encoding="utf-8",
    )

    policy = detect_submission_policy(str(target))

    assert policy.ai_generated_reports_allowed is False
    assert policy.human_attestation_required is True
    assert policy.submission_ready is False
    assert "automatic ban" in policy.quote
    assert policy.reporting_url.endswith("/security/advisories/new")
    assert policy.escalation_email == "security@example.test"


def test_enforce_email_policy_marks_internal_draft(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.mkdir()
    (target / "SECURITY.md").write_text(
        "We do not accept AI generated security reports.\n", encoding="utf-8"
    )
    disclosure = tmp_path / "disclosure"
    disclosure.mkdir()
    email = disclosure / "email.txt"
    email.write_text("Subject: Test\n\nBody.\n", encoding="utf-8")
    policy = detect_submission_policy(str(target))

    enforce_email_policy(str(disclosure), policy)

    content = email.read_text(encoding="utf-8")
    assert "X-CodeAuditor-Submission: blocked" in content
    assert "INTERNAL DRAFT — DO NOT SEND" in content


def test_writes_machine_readable_policy(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.mkdir()
    (target / "SECURITY.md").write_text("No AI generated reports.\n", encoding="utf-8")
    policy = detect_submission_policy(str(target))
    path = tmp_path / "submission-policy.json"

    write_submission_policy(str(path), policy)

    payload = json.loads(path.read_text(encoding="utf-8"))
    assert payload["schema_version"] == 1
    assert payload["submission_ready"] is False
