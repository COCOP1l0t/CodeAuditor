from __future__ import annotations

import hashlib
import posixpath
import re
import stat
import zipfile
import zlib
from pathlib import Path, PurePosixPath

from ..config import ValidationIssue
from ..cvss import report_score_errors
from ..disclosures import extract_email_subject

_REQUIRED_REPORT_SECTIONS = [
    "Summary",
    "Why This Is a Security Issue",
    "Severity Assessment",
    "Security Impact",
    "Root Cause",
    "Reproduction",
]
_MAX_DOCUMENT_BYTES = 4 * 1024 * 1024
_MAX_ARCHIVE_BYTES = 256 * 1024 * 1024
_MAX_ARCHIVE_MEMBERS = 4096


def _report_sections(text: str) -> tuple[dict[str, str], bool]:
    """Read Markdown headings outside fenced code, including nested sections."""
    sections: dict[str, list[str]] = {}
    active: list[tuple[int, str]] = []
    fence = ""
    for line in text.splitlines():
        marker = re.match(r"^\s{0,3}(`{3,}|~{3,})", line)
        if marker:
            token = marker[1]
            if not fence:
                fence = token
            elif token[0] == fence[0] and len(token) >= len(fence):
                fence = ""
            for _, key in active:
                sections[key].append(line)
            continue
        heading = (
            re.match(r"^\s{0,3}(#{1,6})\s+(.+?)\s*#*\s*$", line) if not fence else None
        )
        if heading:
            depth = len(heading[1])
            key = heading[2].strip().casefold()
            active = [(d, k) for d, k in active if d < depth]
            sections.setdefault(key, [])
            active.append((depth, key))
        else:
            for _, key in active:
                sections[key].append(line)
    return {k: "\n".join(v).strip() for k, v in sections.items()}, bool(fence)


def validate_stage6_disclosure(disclosure_dir: str) -> list[ValidationIssue]:
    """Statically validate documents and package consistency; execute nothing."""
    base = Path(disclosure_dir)
    issues: list[ValidationIssue] = []

    def issue(description: str) -> None:
        issues.append(
            ValidationIssue(
                description=description,
                expected="Complete, internally consistent disclosure documents and registered files.",
                fix="Review the original evidence and correct the document or package metadata; do not invent evidence.",
            )
        )

    documents: dict[str, str] = {}
    for name in ("report.md", "email.txt", "disclosure.zip"):
        path = base / name
        if not path.is_file() or path.is_symlink():
            issue(f"Missing required regular disclosure artifact: {name}")
            continue
        if name.endswith(".zip"):
            continue
        try:
            if path.stat().st_size > _MAX_DOCUMENT_BYTES:
                issue(f"Disclosure document exceeds size limit: {name}")
                continue
            documents[name] = path.read_text(encoding="utf-8")
            if not documents[name].strip():
                issue(f"Empty disclosure document: {name}")
        except (OSError, UnicodeError) as exc:
            issue(f"Unreadable disclosure document {name}: {exc}")

    report = documents.get("report.md")
    if report:
        sections, unclosed = _report_sections(report)
        github = all(k in sections for k in ("summary", "details", "poc", "impact"))
        required = (
            ["Summary", "Details", "PoC", "Impact"]
            if github
            else _REQUIRED_REPORT_SECTIONS
        )
        for section in required:
            key = section.casefold()
            if key == "reproduction" and key not in sections:
                key = "reproduction steps"
            if key not in sections:
                issue(f"Missing required section in disclosure report: {section}")
            elif not sections[key]:
                issue(f"Empty required section in disclosure report: {section}")
        if unclosed:
            issue("Unclosed fenced code block in disclosure report")
        for error in report_score_errors(report, require_vector=not github):
            issue(error)
        if re.search(
            r"\b(?:Finding|Audit|Vulnerability) ID\b.*\b[CHML]-\d{2}\b", report
        ):
            issue("Internal audit identifier in disclosure report metadata")
        if re.search(
            r"/home/[^/\s]+/\.code_auditor/|/tmp/code-auditor/|stage[456]-(?:disclosures|pocs|vulnerabilities)/",
            report,
        ):
            issue("Internal workspace path in disclosure report")

    email = documents.get("email.txt")
    if email:
        subject = extract_email_subject(str(base / "email.txt"))
        if not subject:
            issue("Missing Subject line in disclosure email header")
        if not re.search(r"\n[ \t]*\n", email):
            issue("Disclosure email must separate headers and body with a blank line")
        for line in re.split(r"\n[ \t]*\n", email, maxsplit=1)[0].splitlines():
            if (
                line
                and not line.startswith((" ", "\t"))
                and not re.match(r"[A-Za-z][A-Za-z-]*:", line)
            ):
                issue("Unindented continuation in disclosure email header")
                break

    archive_path = base / "disclosure.zip"
    if archive_path.is_file() and not archive_path.is_symlink():
        try:
            with zipfile.ZipFile(archive_path) as archive:
                members = archive.infolist()
                if (
                    len(members) > _MAX_ARCHIVE_MEMBERS
                    or sum(i.file_size for i in members) > _MAX_ARCHIVE_BYTES
                ):
                    issue("Disclosure archive exceeds static validation size limit")
                    return issues
                names = [i.filename for i in members]
                if len(set(names)) != len(names):
                    issue("Duplicate archive member names")
                reports = [
                    i
                    for i in members
                    if not i.is_dir() and PurePosixPath(i.filename).name == "report.md"
                ]
                if len(reports) != 1:
                    issue("Disclosure archive must contain exactly one report.md")
                    return issues
                prefix = PurePosixPath(reports[0].filename).parent
                for member in members:
                    path = PurePosixPath(member.filename)
                    if (
                        path.is_absolute()
                        or ".." in path.parts
                        or chr(92) in member.filename
                    ):
                        issue(f"Unsafe disclosure archive member: {member.filename}")
                        continue
                    if member.is_dir():
                        continue
                    if path.name == "email.txt":
                        issue("email.txt belongs outside the disclosure archive")
                    if "__pycache__" in path.parts or path.suffix in {".pyc", ".pyo"}:
                        issue(
                            f"Generated cache file in disclosure archive: {member.filename}"
                        )
                    try:
                        relative = path.relative_to(prefix)
                    except ValueError:
                        issue(
                            f"Archive member is outside the report directory: {member.filename}"
                        )
                        continue
                    local = base / str(relative)
                    if stat.S_ISLNK(member.external_attr >> 16):
                        if member.file_size > 4096:
                            issue(f"Oversized archive symlink: {member.filename}")
                            continue
                        target = archive.read(member).decode("utf-8")
                        resolved = posixpath.normpath(str(path.parent / target))
                        if (
                            target.startswith("/")
                            or chr(92) in target
                            or "\x00" in target
                            or resolved == ".."
                            or resolved.startswith("../")
                            or not PurePosixPath(resolved).is_relative_to(prefix)
                        ):
                            issue(f"Unsafe archive symlink target: {member.filename}")
                        elif local.is_symlink() and str(local.readlink()) != target:
                            issue(
                                f"Archive and local symlink differ: {member.filename}"
                            )
                        elif local.exists() and not local.is_symlink():
                            issue(
                                f"Archive symlink has a non-symlink counterpart: {member.filename}"
                            )
                        continue
                    archived = hashlib.sha256()
                    with archive.open(member) as source:
                        while chunk := source.read(65536):
                            archived.update(chunk)
                    # A standalone ZIP may be the only retained copy of a
                    # support file. Compare counterparts that actually exist.
                    if not local.exists():
                        continue
                    if (
                        not local.resolve().is_relative_to(base.resolve())
                        or local.is_symlink()
                        or not local.is_file()
                    ):
                        issue(f"Unsafe local counterpart: {member.filename}")
                        continue
                    if local.stat().st_size != member.file_size:
                        issue(f"Archive and local file differ: {member.filename}")
                        continue
                    with local.open("rb") as source:
                        local_hash = hashlib.file_digest(source, "sha256").digest()
                    if archived.digest() != local_hash:
                        issue(f"Archive and local file differ: {member.filename}")
        except (
            OSError,
            ValueError,
            UnicodeError,
            RuntimeError,
            zipfile.BadZipFile,
            NotImplementedError,
            zlib.error,
        ) as exc:
            issue(f"Unreadable or corrupt disclosure archive: {exc}")
    return issues
