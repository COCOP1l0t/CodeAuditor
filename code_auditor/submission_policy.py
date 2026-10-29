"""Target-repository submission policy detection for Disclosure outputs."""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass
from pathlib import Path

from .secure_fs import write_private_bytes_atomic


@dataclass(frozen=True)
class SubmissionPolicy:
    source: str
    ai_generated_reports_allowed: bool
    human_attestation_required: bool
    submission_ready: bool
    quote: str
    reporting_url: str
    escalation_email: str
    reason: str


_AI_REPORT_RE = re.compile(
    r"(?:do\s+not|does\s+not|won't|will\s+not)\s+accept[^\n]{0,120}"
    r"(?:AI[-\s]?generated|AI[-\s]?assisted)[^\n]{0,120}"
    r"|\bno\s+(?:AI[-\s]?generated|AI[-\s]?assisted)\s+(?:security\s+)?reports?\b"
    r"|(?:AI[-\s]?generated|AI[-\s]?assisted)[^\n]{0,120}"
    r"(?:automatic\s+ban|not\s+accepted|rejected)",
    re.IGNORECASE,
)
_ADVISORY_RE = re.compile(
    r"https?://github\.com/[^\s)>\]]+/security/advisories/new", re.IGNORECASE
)
_EMAIL_RE = re.compile(r"\bsecurity@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")


def _policy_path(target: str) -> Path | None:
    root = Path(target)
    for relative in ("SECURITY.md", ".github/SECURITY.md", "docs/SECURITY.md"):
        candidate = root / relative
        if candidate.is_file() and not candidate.is_symlink():
            return candidate
    return None


def detect_submission_policy(target: str) -> SubmissionPolicy:
    path = _policy_path(target)
    if path is None:
        return SubmissionPolicy(
            source="",
            ai_generated_reports_allowed=True,
            human_attestation_required=False,
            submission_ready=True,
            quote="",
            reporting_url="",
            escalation_email="",
            reason="No SECURITY.md policy file was found.",
        )
    text = path.read_text(encoding="utf-8", errors="replace")
    match = _AI_REPORT_RE.search(text)
    advisory = _ADVISORY_RE.search(text)
    email = _EMAIL_RE.search(text)
    quote = ""
    if match:
        start = max(0, text.rfind("\n", 0, match.start()) + 1)
        end = text.find("\n", match.end())
        quote = text[start : end if end >= 0 else len(text)].strip()
    blocked = match is not None
    return SubmissionPolicy(
        source=str(path),
        ai_generated_reports_allowed=not blocked,
        human_attestation_required=blocked,
        submission_ready=not blocked,
        quote=quote,
        reporting_url=advisory.group(0) if advisory else "",
        escalation_email=email.group(0) if email else "",
        reason=(
            "The target rejects AI-generated or AI-assisted security reports; "
            "human validation and a human-authored rewrite are required before submission."
            if blocked
            else "No AI-report submission prohibition was detected."
        ),
    )


def write_submission_policy(path: str, policy: SubmissionPolicy) -> None:
    payload = {
        "schema_version": 1,
        **asdict(policy),
    }
    data = (json.dumps(payload, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
    write_private_bytes_atomic(path, data)


def enforce_email_policy(disclosure_dir: str, policy: SubmissionPolicy) -> None:
    """Mark generated email as internal-only when the target forbids AI reports."""
    if policy.submission_ready:
        return
    email_path = Path(disclosure_dir) / "email.txt"
    if not email_path.is_file() or email_path.is_symlink():
        return
    text = email_path.read_text(encoding="utf-8", errors="replace")
    if "X-CodeAuditor-Submission: blocked" in text:
        return
    header = (
        "X-CodeAuditor-Submission: blocked\n"
        "X-CodeAuditor-Policy: target rejects AI-generated or AI-assisted reports\n"
    )
    marker = "INTERNAL DRAFT — DO NOT SEND WITHOUT INDEPENDENT HUMAN VALIDATION\n\n"
    if text.startswith("Subject:"):
        first, separator, rest = text.partition("\n\n")
        text = first + "\n" + header + separator + marker + rest
    else:
        text = header + "\n" + marker + text
    email_path.write_text(text, encoding="utf-8")
