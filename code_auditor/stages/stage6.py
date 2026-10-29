from __future__ import annotations

import contextlib
import json
import os
import re
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..agent import run_agent
from ..checkpoint import CheckpointManager
from ..config import AuditConfig, select_poc_model
from ..disclosures import build_dedupe_key, display_list, single_line
from ..layout import checkpoint_key, stage4_paths, stage6_paths
from ..logger import get_logger
from ..poc_artifacts import stage5_vuln_id
from ..prompts import load_prompt
from ..repos import capture_repo_identity
from ..reproduction_status import (
    is_failed_status,
    is_reproduced_status,
    read_reproduction_status,
)
from ..retention import export_retained_artifacts, secure_generated_manifest_mode
from ..retention import (
    RETAIN_MANIFEST_FILENAME,
    RetentionError,
    load_retain_manifest,
    write_retain_manifest_v2,
)
from ..sandbox import DockerScratch, docker_scratch
from ..stage_runtime import finalize_checkpoint
from ..submission_policy import (
    SubmissionPolicy,
    detect_submission_policy,
    enforce_email_policy,
    write_submission_policy,
)
from ..utils import collect_parallel_results, extract_json_object, run_parallel_limited
from ..validation.stage5 import validate_stage5_trigger_graph
from ..validation.stage6 import _report_sections, validate_stage6_disclosure
from ..wiki import build_wiki_context

logger = get_logger("stage6")

# Stage 6 agents verify reproduction, create minimal PoCs, and write
# polished disclosure artifacts — similar complexity to Stage 5.
_MAX_TURNS = 500
_DEFAULT_EFFORT = "medium"


@dataclass(frozen=True)
class _DisclosureCandidate:
    report_path: str
    vuln_id: str | None
    title: str
    finding: dict[str, Any]
    finding_path: str | None
    dedupe_key: str


def _task_key(vuln_id: str) -> str:
    return checkpoint_key(6, vuln_id)


def _stage5_evidence_status(
    report_path: str,
    config: AuditConfig,
) -> tuple[bool, str]:
    """Return whether Stage 5's retained evidence can be reused verbatim."""
    poc_dir = Path(report_path).parent
    status = read_reproduction_status(report_path)
    if not is_reproduced_status(status):
        return False, f"Stage 5 reproduction status is {status or 'missing'}"
    vuln_id = stage5_vuln_id(poc_dir.name)
    if vuln_id is None:
        return False, "Stage 5 vulnerability id is invalid"
    graph_issues = validate_stage5_trigger_graph(str(poc_dir), vuln_id)
    if graph_issues:
        return False, "trigger graph is missing or invalid"
    # Agents commonly create manifests with the process umask. Tightening this
    # single known metadata file is deterministic and required by the retention
    # contract; it does not change any retained content hash.
    secure_generated_manifest_mode(str(poc_dir))
    try:
        load_retain_manifest(
            poc_dir,
            required_paths=("report.md", "reproduce.sh"),
            max_file_bytes=config.retain_max_file_bytes,
            max_total_bytes=config.retain_max_total_bytes,
        )
    except RetentionError as exc:
        return False, f"retained evidence manifest is invalid: {exc}"
    return True, "Stage 5 report, trigger graph, retained manifest, sizes, and hashes are valid"


def _submission_policy_context(policy: SubmissionPolicy) -> str:
    if policy.submission_ready:
        return (
            "No target policy blocks generated reports. Still require independent "
            "human validation before external submission."
        )
    return (
        "TARGET SUBMISSION POLICY BLOCK: "
        f"{policy.reason} Source: {policy.source}. "
        f"Policy quote: {policy.quote or '(not extracted)'} "
        "The email must be clearly marked as an internal draft and must not be "
        "presented as ready to send."
    )


def _normalize_disclosure_package(disclosure_dir: str) -> None:
    """Rebuild the ZIP at its root and refresh hashes after email policy edits."""
    base = Path(disclosure_dir)
    manifest_path = base / RETAIN_MANIFEST_FILENAME
    if not manifest_path.is_file() or manifest_path.is_symlink():
        return
    try:
        raw = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, ValueError, json.JSONDecodeError):
        return

    entrypoint_data = raw.get("entrypoint") if isinstance(raw, dict) else None
    if isinstance(entrypoint_data, str):
        entrypoint = entrypoint_data
        platform = "linux"
        interpreter = "sh"
        argv: tuple[str, ...] = ()
    elif isinstance(entrypoint_data, dict):
        entrypoint = entrypoint_data.get("path")
        platform = entrypoint_data.get("platform")
        interpreter = entrypoint_data.get("interpreter")
        raw_argv = entrypoint_data.get("argv", [])
        argv = tuple(raw_argv) if isinstance(raw_argv, list) else ()
    else:
        return
    if not all(isinstance(value, str) and value for value in (entrypoint, platform, interpreter)):
        return

    raw_entries = raw.get("files") if isinstance(raw, dict) else None
    if not isinstance(raw_entries, list):
        return
    role_by_path: dict[str, str] = {}
    for entry in raw_entries:
        if not isinstance(entry, dict):
            continue
        path = entry.get("path")
        role = entry.get("role")
        if isinstance(path, str) and isinstance(role, str):
            role_by_path[path] = role

    required = {"report.md", "reproduce.sh", "email.txt", "disclosure.zip"}
    for name in required:
        if role_by_path.get(name):
            continue
        role_by_path[name] = (
            "entrypoint"
            if name == "reproduce.sh"
            else "report"
            if name == "report.md"
            else "disclosure"
        )

    zip_roles = {"entrypoint", "script", "support", "report", "evidence", "input"}
    zip_paths = [
        path
        for path, role in sorted(role_by_path.items())
        if path not in {"email.txt", "disclosure.zip"}
        and role in zip_roles
        and (base / path).is_file()
    ]
    temporary = base / ".disclosure.zip.tmp"
    with zipfile.ZipFile(temporary, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for relative in zip_paths:
            archive.write(base / relative, arcname=relative)
    os.replace(temporary, base / "disclosure.zip")

    retained_paths = [
        path
        for path in role_by_path
        if path != RETAIN_MANIFEST_FILENAME and (base / path).is_file()
    ]
    write_retain_manifest_v2(
        base,
        entrypoint=entrypoint,
        platform=platform,
        interpreter=interpreter,
        argv=argv,
        files=[(path, role_by_path[path]) for path in sorted(retained_paths)],
    )


def _vuln_id_from_report(report_path: str) -> str | None:
    """Extract vulnerability ID from a stage 5 report path.

    Expects paths like .../stage5-pocs/{vuln_id}/report.md. The directory name
    is validated with the shared Stage 5 id rules, so a false-positive or
    malformed directory can never become a disclosure directory or checkpoint
    marker name.
    """
    return stage5_vuln_id(Path(report_path).parent.name)


def _find_finding_file(vuln_id: str, output_dir: str) -> str | None:
    """Locate the stage 4 evaluated finding JSON for a vulnerability ID."""
    path = os.path.join(
        stage4_paths(output_dir)["directory"], f"{vuln_id}.json"
    )
    return path if os.path.exists(path) else None


def _read_text(path: str) -> str:
    try:
        return Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _extract_report_title(report_path: str) -> str | None:
    """Return the first Markdown heading outside fenced code blocks."""
    content = _read_text(report_path)
    fence = ""
    for line in content.splitlines():
        marker = re.match(r"^\s{0,3}(`{3,}|~{3,})", line)
        if marker:
            token = marker[1]
            if not fence:
                fence = token
            elif token[0] == fence[0] and len(token) >= len(fence):
                fence = ""
            continue
        if fence:
            continue
        heading = re.match(r"^\s{0,3}#{1,6}\s+(.+?)\s*#*\s*$", line)
        if heading:
            title = heading[1].strip()
            if title:
                return title
    return None


def _extract_report_section(content: str, heading: str) -> str | None:
    # Reuse the validator's fence-aware section parser so a ``# comment`` inside
    # a shell block cannot truncate a section or be mistaken for a heading.
    sections, _ = _report_sections(content)
    return sections.get(heading.strip().casefold()) or None


def _fallback_finding_from_report(
    report_path: str, vuln_id: str | None
) -> dict[str, Any]:
    """Build deterministic finding metadata when Stage 4 JSON is unavailable."""
    content = _read_text(report_path)
    title = _extract_report_title(report_path) or vuln_id or Path(report_path).stem
    trigger = _extract_report_section(content, "Trigger") or title
    summary = (
        _extract_report_section(content, "Summary")
        or _extract_report_section(content, "Reproduction")
        or "Stage 5 reproduction report was processed without a valid Stage 4 finding."
    )
    location = _extract_report_section(content, "Location")
    fallback_location = single_line(location) if location else f"stage5-report:{title}"

    return {
        "id": vuln_id or Path(report_path).parent.name,
        "title": title,
        "location": fallback_location,
        "trigger": single_line(trigger)[:500],
        "summary": single_line(summary)[:500],
        "cwe_id": [],
        "vulnerability_class": [],
    }


def _load_candidate(
    report_path: str, config: AuditConfig, repo_url: str
) -> _DisclosureCandidate:
    vuln_id = _vuln_id_from_report(report_path)
    finding_path = _find_finding_file(vuln_id, config.output_dir) if vuln_id else None
    finding: dict[str, Any] | None = None

    if finding_path:
        try:
            loaded = json.loads(Path(finding_path).read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                finding = loaded
            else:
                logger.warning(
                    "Stage 6: Finding JSON for %s is not an object; using fallback dedupe metadata.",
                    vuln_id or report_path,
                )
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            logger.warning(
                "Stage 6: Could not read finding JSON for %s at %s: %s; using fallback dedupe metadata.",
                vuln_id or report_path,
                finding_path,
                exc,
            )

    if finding is None:
        finding = _fallback_finding_from_report(report_path, vuln_id)

    title = (
        single_line(finding.get("title"))
        or _extract_report_title(report_path)
        or vuln_id
        or report_path
    )
    return _DisclosureCandidate(
        report_path=report_path,
        vuln_id=vuln_id,
        title=title,
        finding=finding,
        finding_path=finding_path,
        dedupe_key=build_dedupe_key(finding, repo_url),
    )


def _candidate_label(candidate: _DisclosureCandidate) -> str:
    if candidate.vuln_id and candidate.title:
        return f"{candidate.vuln_id} ({candidate.title})"
    return candidate.vuln_id or candidate.title or candidate.report_path


def _filter_known_duplicates(
    stage5_reports: list[str],
    config: AuditConfig,
    repo_url: str,
    existing_entries: tuple[dict[str, Any], ...],
) -> list[_DisclosureCandidate]:
    existing_keys = {
        str(entry.get("dedupe_key") or "")
        for entry in existing_entries
        if entry.get("dedupe_key")
    }
    seen_keys: set[str] = set()
    candidates: list[_DisclosureCandidate] = []

    for report_path in stage5_reports:
        candidate = _load_candidate(report_path, config, repo_url)
        label = _candidate_label(candidate)

        if candidate.dedupe_key in existing_keys:
            logger.info(
                "Stage 6: Skipping already discovered vulnerability %s (dedupe_key=%s).",
                label,
                candidate.dedupe_key,
            )
            continue

        if candidate.dedupe_key in seen_keys:
            logger.info(
                "Stage 6: Skipping duplicate vulnerability in current Stage 6 input %s (dedupe_key=%s).",
                label,
                candidate.dedupe_key,
            )
            continue

        seen_keys.add(candidate.dedupe_key)
        candidates.append(candidate)

    return candidates


_MAX_DEDUPE_TURNS = 30
_DEFAULT_DEDUPE_EFFORT = "low"


async def _filter_semantic_duplicates(
    candidates: list[_DisclosureCandidate],
    existing_entries: tuple[dict[str, Any], ...],
    config: AuditConfig,
) -> list[_DisclosureCandidate]:
    """Compare candidates against database-backed Disclosure metadata."""
    logger.info(
        "Stage 6: Running semantic deduplication against %d existing entries.",
        len(existing_entries),
    )

    inventory = list(existing_entries)
    existing_keys = {
        str(entry.get("dedupe_key") or "")
        for entry in existing_entries
        if entry.get("dedupe_key")
    }

    filtered: list[_DisclosureCandidate] = []
    for candidate in candidates:
        label = _candidate_label(candidate)
        entry = {
            "dedupe_key": candidate.dedupe_key,
            "title": candidate.title,
            "location": single_line(candidate.finding.get("location")),
            "cwe": ", ".join(
                display_list(
                    candidate.finding.get("cwe_id") or candidate.finding.get("cwe")
                )
            ),
            "vulnerability_class": ", ".join(
                display_list(candidate.finding.get("vulnerability_class"))
            ),
            "trigger": single_line(candidate.finding.get("trigger")),
            "summary": single_line(
                candidate.finding.get("summary") or candidate.finding.get("description")
            ),
        }
        if not inventory:
            filtered.append(candidate)
            inventory.append(entry)
            existing_keys.add(candidate.dedupe_key)
            continue
        phase = "prompt preparation"
        try:
            existing_text = "\n\n".join(
                f"Entry {i + 1}\n"
                + "\n".join(f"- {key}: {known.get(key, '')}" for key in entry)
                for i, known in enumerate(inventory)
            )
            prompt = load_prompt(
                "stage6_semantic_dedupe.md",
                {
                    "candidate_title": candidate.title,
                    "candidate_location": single_line(candidate.finding.get("location")),
                    "candidate_cwe": ", ".join(
                        display_list(
                            candidate.finding.get("cwe_id") or candidate.finding.get("cwe")
                        )
                    ),
                    "candidate_vuln_class": ", ".join(
                        display_list(candidate.finding.get("vulnerability_class"))
                    ),
                    "candidate_trigger": single_line(candidate.finding.get("trigger")),
                    "candidate_summary": single_line(
                        candidate.finding.get("summary")
                        or candidate.finding.get("description")
                    ),
                    "existing_entries": existing_text,
                },
            )

            log_file = os.path.join(
                stage6_paths(config.output_dir)["directory"],
                ".dedupe-logs",
                f"{candidate.vuln_id or 'unknown'}.log",
            )
            phase = "agent call"
            result = await run_agent(
                prompt,
                config,
                cwd=config.target,
                max_turns=_MAX_DEDUPE_TURNS,
                effort=_DEFAULT_DEDUPE_EFFORT,
                log_file=log_file,
            )
            phase = "response validation"
            json_text = extract_json_object(result)
            if json_text is None:
                raise json.JSONDecodeError(
                    "No JSON object found in response", result, 0
                )
            parsed = json.loads(json_text)
            decision = str(parsed.get("decision", "")).lower()
            matched_key = str(parsed.get("matched_dedupe_key", ""))
            reason = str(parsed.get("reason", ""))

            if decision == "duplicate":
                if matched_key not in existing_keys:
                    raise ValueError(
                        "duplicate decision referenced a dedupe key that was not "
                        "present in the supplied Disclosure inventory"
                    )
                logger.info(
                    "Stage 6: Semantic dedupe filtered %s as duplicate of %s. Reason: %s",
                    label,
                    matched_key,
                    reason,
                )
                continue
            if decision != "new":
                raise ValueError(f"unsupported semantic dedupe decision: {decision!r}")
            if matched_key:
                raise ValueError("new decision must use an empty matched_dedupe_key")
        except Exception as exc:
            logger.warning(
                "Stage 6: Semantic dedupe %s failed for %s: %s. Keeping candidate.",
                phase,
                label,
                exc,
            )

        filtered.append(candidate)
        # Later candidates must also see this batch's retained metadata.
        inventory.append(entry)
        existing_keys.add(candidate.dedupe_key)

    logger.info(
        "Stage 6: Semantic dedupe kept %d/%d candidates.",
        len(filtered),
        len(candidates),
    )
    return filtered


async def _select_disclosure_candidates(
    stage5_reports: list[str],
    config: AuditConfig,
    repo_url: str,
) -> list[_DisclosureCandidate]:
    """Apply exact and semantic deduplication before disclosure generation."""
    candidates = _filter_known_duplicates(
        stage5_reports,
        config,
        repo_url,
        config.known_disclosures,
    )
    if not candidates:
        logger.info(
            "Stage 6: No new reproduced vulnerabilities to prepare disclosures for after database dedupe."
        )
        return []

    candidates = await _filter_semantic_duplicates(
        candidates,
        config.known_disclosures,
        config,
    )
    if not candidates:
        logger.info(
            "Stage 6: No new reproduced vulnerabilities to prepare disclosures for after semantic dedupe."
        )
    return candidates


def _filter_reproduced(stage5_reports: list[str]) -> list[str]:
    """Keep only Stage 5 reports from successful reproductions."""
    reproduced: list[str] = []
    for report_path in stage5_reports:
        report_dir = Path(report_path).parent
        if report_dir.name.endswith("_fp"):
            logger.info(
                "Stage 6: Skipping false-positive Stage 5 report: %s", report_path
            )
            continue

        status = read_reproduction_status(report_path)
        if is_failed_status(status):
            logger.info(
                "Stage 6: Skipping Stage 5 report with reproduction status %s: %s",
                status,
                report_path,
            )
            continue

        if not is_reproduced_status(status):
            logger.warning(
                "Stage 6: Skipping Stage 5 report with missing or unknown reproduction status: %s",
                report_path,
            )
            continue

        reproduced.append(report_path)

    return reproduced


async def _run_disclosure(
    report_path: str,
    config: AuditConfig,
    checkpoint: CheckpointManager,
) -> str | None:
    """Prepare disclosure artifacts for a single reproduced vulnerability."""
    vuln_id = _vuln_id_from_report(report_path)
    if not vuln_id:
        logger.warning(
            "Stage 6: Cannot extract vuln ID from %s, skipping.", report_path
        )
        return None

    key = _task_key(vuln_id)
    persistent_stage6_vuln_dir = os.path.join(
        stage6_paths(config.output_dir)["directory"], vuln_id
    )
    persistent_disclosure_dir = os.path.join(persistent_stage6_vuln_dir, "disclosure")
    persistent_disclosure_report = os.path.join(persistent_disclosure_dir, "report.md")
    submission_policy = detect_submission_policy(config.target)
    submission_policy_path = os.path.join(
        persistent_stage6_vuln_dir, "submission-policy.json"
    )

    if checkpoint.is_complete(key):
        issues = validate_stage6_disclosure(persistent_disclosure_dir)
        if issues:
            checkpoint.clear(key)
            raise ValueError(
                f"Stage 6: Invalid completed artifacts for {vuln_id}: "
                + "; ".join(issue.description for issue in issues)
            )
        email_path = Path(persistent_disclosure_dir) / "email.txt"
        email_text = _read_text(str(email_path))
        if (
            not submission_policy.submission_ready
            and "X-CodeAuditor-Submission: blocked" not in email_text
        ):
            logger.warning(
                "Stage 6: %s predates the submission-policy guard; regenerating.", vuln_id
            )
            checkpoint.clear(key)
        else:
            os.makedirs(persistent_stage6_vuln_dir, exist_ok=True)
            write_submission_policy(submission_policy_path, submission_policy)
            logger.info("Stage 6: %s already complete and validated, skipping.", vuln_id)
            return persistent_disclosure_report

    logger.info("Stage 6: Starting disclosure preparation for %s.", vuln_id)
    poc_dir = str(Path(report_path).parent)
    finding_file = _find_finding_file(vuln_id, config.output_dir)
    evidence_ok, evidence_reason = _stage5_evidence_status(report_path, config)
    if evidence_ok:
        evidence_context = (
            f"{evidence_reason}. Reuse the Stage 5 retained report, evidence files, "
            "reproduce entrypoint, manifest, and hashes. Do not rebuild the target or "
            "rerun the PoC unless you discover a concrete missing or invalid artifact. "
            "Create the disclosure report and email from the retained evidence; preserve "
            "the verified observed output and do not invent new runtime results."
        )
        logger.info("Stage 6: Reusing validated Stage 5 evidence for %s.", vuln_id)
    else:
        evidence_context = (
            f"Stage 5 evidence cannot be reused: {evidence_reason}. Re-verify the "
            "reproduction and repair only the missing or invalid artifacts before "
            "packaging the disclosure."
        )
        logger.warning("Stage 6: Stage 5 evidence reuse rejected for %s: %s", vuln_id, evidence_reason)
    if config.sandbox_enabled:
        identity = capture_repo_identity(config.target)
        source_commit = config.poc_source_commit or identity.get("commit") or ""
        scratch_cm = docker_scratch(
            config,
            f"stage6-{vuln_id}",
            source_commit=source_commit,
            logger=logger,
            scratch_factory=DockerScratch,
        )
    else:
        scratch_cm = contextlib.nullcontext(None)

    async with scratch_cm as sandbox:
        work_config = config
        work_report_path = report_path
        if sandbox is not None:
            work_config = sandbox.audit_config(config)
            copied_poc_dir = sandbox.copy_input_tree(poc_dir, "stage5-poc")
            poc_dir = str(copied_poc_dir)
            work_report_path = str(copied_poc_dir / "report.md")
            if finding_file:
                finding_file = str(sandbox.copy_input(finding_file, "finding.json"))

        stage6_vuln_dir = os.path.join(
            stage6_paths(work_config.output_dir)["directory"], vuln_id
        )
        disclosure_dir = os.path.join(stage6_vuln_dir, "disclosure")
        disclosure_report = os.path.join(disclosure_dir, "report.md")
        os.makedirs(disclosure_dir, exist_ok=True)

        if finding_file:
            finding_reference = (
                "The evaluated finding with detailed data-flow trace, CWE, "
                "and CVSS analysis is at:\n\n"
                f"`{finding_file}`\n\n"
                "Read this file for additional context on the vulnerability."
            )
        else:
            finding_reference = (
                "No evaluated finding file is available. "
                "Use the vulnerability report for all details."
            )

        poc_target = work_config.poc_worktree or work_config.target

        prompt = load_prompt(
            "stage6.md",
            {
                "vuln_report_path": work_report_path,
                "poc_dir": poc_dir,
                "finding_reference": finding_reference,
                "target_path": poc_target,
                "disclosure_dir": disclosure_dir,
                "vuln_id": vuln_id,
                "stage5_evidence_context": evidence_context,
                "submission_policy_context": _submission_policy_context(
                    submission_policy
                ),
                "wiki_context": build_wiki_context(config, stage=6),
            },
        )

        log_file = os.path.join(stage6_vuln_dir, "agent.log")
        current_prompt = prompt
        issues = []
        for attempt in range(2):
            await run_agent(
                current_prompt,
                work_config,
                cwd=poc_target,
                max_turns=_MAX_TURNS,
                model=select_poc_model(config),
                effort=_DEFAULT_EFFORT,
                log_file=log_file,
                sandbox=sandbox,
            )
            enforce_email_policy(disclosure_dir, submission_policy)
            _normalize_disclosure_package(disclosure_dir)
            # Local-worktree agents commonly create metadata with the process
            # umask too; harden before validation instead of only after export.
            secure_generated_manifest_mode(disclosure_dir)
            issues = validate_stage6_disclosure(disclosure_dir)
            if not issues:
                break
            if attempt:
                raise ValueError(
                    f"Stage 6: Invalid disclosure artifacts for {vuln_id}: "
                    + "; ".join(issue.description for issue in issues)
                )
            repair_lines = "\n".join(
                f"- {issue.description}" for issue in issues
            )
            current_prompt = (
                prompt
                + "\n\n## Bounded disclosure validation repair pass\n"
                + "Repair only the delivery defects listed below. Do not redo "
                + "vulnerability analysis, invent evidence, or change the "
                + "verified technical conclusion. Preserve the existing PoC "
                + "and observed results.\n"
                + repair_lines
                + "\nUse the canonical report values for the email CVSS text. "
                + "For binary evidence, register the file as an input/support "
                + "artifact instead of forcing it to UTF-8 text."
            )
        if sandbox is not None:
            secure_generated_manifest_mode(disclosure_dir)
            manifest = export_retained_artifacts(
                disclosure_dir,
                persistent_disclosure_dir,
                required_paths=(
                    "report.md",
                    "email.txt",
                    "disclosure.zip",
                    "reproduce.sh",
                ),
                max_file_bytes=config.retain_max_file_bytes,
                max_total_bytes=config.retain_max_total_bytes,
            )
            logger.info(
                "Stage 6: Exported %d retained files (%d bytes) for %s.",
                len(manifest.files),
                manifest.total_bytes,
                vuln_id,
            )
            disclosure_report = persistent_disclosure_report
            issues = validate_stage6_disclosure(persistent_disclosure_dir)
            if issues:
                raise ValueError(
                    f"Stage 6: Invalid retained artifacts for {vuln_id}: "
                    + "; ".join(issue.description for issue in issues)
                )
    finalize_checkpoint(checkpoint, key, valid=True)
    os.makedirs(persistent_stage6_vuln_dir, exist_ok=True)
    write_submission_policy(submission_policy_path, submission_policy)
    has_report = os.path.exists(disclosure_report)
    logger.info("Stage 6: %s complete (report=%s)", vuln_id, has_report)
    return disclosure_report if has_report else None


async def run_stage6(
    stage5_reports: list[str],
    config: AuditConfig,
    checkpoint: CheckpointManager,
    progress: object | None = None,
) -> list[str]:
    """Prepare disclosure artifacts for each reproduced vulnerability in parallel."""
    reproduced = _filter_reproduced(stage5_reports)
    if not reproduced:
        logger.info(
            "Stage 6: No reproduced vulnerabilities to prepare disclosures for."
        )
        return []

    repo_url = capture_repo_identity(config.target).get("repo_url", "")
    if progress is not None:
        progress.update(
            items_done=0,
            items_total=len(reproduced),
            detail="Deduplicating reproduced findings",
        )
    candidates = await _select_disclosure_candidates(
        reproduced,
        config,
        repo_url,
    )
    if not candidates:
        return []

    # Runtime-only counter for the orchestrator's final Stage 6 progress row.
    config.stage6_candidate_total = len(candidates)
    if progress is not None:
        progress.update(
            items_done=0,
            items_total=len(candidates),
            detail=f"Preparing {len(candidates)} deduplicated disclosures",
        )
    logger.info(
        "Stage 6: Preparing disclosures for %d reproduced vulnerabilities after dedupe.",
        len(candidates),
    )

    completed = 0

    def task_complete(index: int, candidate: _DisclosureCandidate) -> None:
        nonlocal completed
        completed += 1
        if progress is not None:
            progress.update(
                items_done=completed,
                items_total=len(candidates),
                detail=f"Prepared {completed}/{len(candidates)} disclosure packages",
            )

    results = await run_parallel_limited(
        candidates,
        config.max_parallel,
        lambda candidate, _: _run_disclosure(candidate.report_path, config, checkpoint),
        on_complete=task_complete,
    )

    disclosure_reports = collect_parallel_results(
        results,
        candidates,
        stage="stage6",
        config=config,
        logger=logger,
        item_id=lambda candidate: os.path.basename(
            os.path.dirname(candidate.report_path)
        ),
        item_log=lambda candidate: os.path.basename(candidate.report_path),
    )

    logger.info(
        "Stage 6 complete. %d disclosure packages prepared (from %d reproduced vulnerabilities).",
        len(disclosure_reports),
        len(candidates),
    )
    return disclosure_reports
