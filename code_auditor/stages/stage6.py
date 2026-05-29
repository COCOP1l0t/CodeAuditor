from __future__ import annotations

import asyncio
import json
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..agent import run_agent
from ..checkpoint import CheckpointManager
from ..config import AuditConfig, resolve_discovered_path, select_poc_model
from ..discovered import (
    append_entries,
    build_dedupe_key,
    build_discovered_entry,
    collect_repo_snapshot,
    read_discovered_entries,
    read_discovered_keys,
)
from ..logger import get_logger
from ..prompts import load_prompt
from ..reproduction_status import is_failed_status, is_reproduced_status, read_reproduction_status
from ..utils import run_parallel_limited
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
    return f"stage6:{vuln_id}"


def _vuln_id_from_report(report_path: str) -> str | None:
    """Extract vulnerability ID from a stage 5 report path.

    Expects paths like .../stage5-pocs/{vuln_id}/report.md
    """
    parent = Path(report_path).parent
    name = parent.name
    if name.endswith("_fp"):
        return None
    return name


def _find_finding_file(vuln_id: str, output_dir: str) -> str | None:
    """Locate the stage 4 evaluated finding JSON for a vulnerability ID."""
    path = os.path.join(output_dir, "stage4-vulnerabilities", f"{vuln_id}.json")
    return path if os.path.exists(path) else None


def _read_text(path: str) -> str:
    try:
        return Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _single_line(value: object) -> str:
    return " ".join(str(value or "").strip().split())


def _display_list(value: object) -> list[str]:
    if isinstance(value, (list, tuple, set)):
        return [_single_line(item) for item in value if _single_line(item)]
    text = _single_line(value)
    return [text] if text else []


def _extract_report_title(report_path: str) -> str | None:
    content = _read_text(report_path)
    for line in content.splitlines():
        stripped = line.strip()
        if stripped.startswith("#"):
            title = stripped.lstrip("#").strip()
            if title:
                return title
    return None


def _extract_report_section(content: str, heading: str) -> str | None:
    heading_re = re.compile(rf"^\s*#+\s+{re.escape(heading)}\s*$", re.IGNORECASE)
    lines = content.splitlines()
    for index, line in enumerate(lines):
        if not heading_re.match(line):
            continue
        section_lines: list[str] = []
        for next_line in lines[index + 1 :]:
            if next_line.lstrip().startswith("#"):
                break
            section_lines.append(next_line)
        text = "\n".join(section_lines).strip()
        if text:
            return text
    return None


def _fallback_finding_from_report(report_path: str, vuln_id: str | None) -> dict[str, Any]:
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
    fallback_location = _single_line(location) if location else f"stage5-report:{title}"

    return {
        "id": vuln_id or Path(report_path).parent.name,
        "title": title,
        "location": fallback_location,
        "trigger": _single_line(trigger)[:500],
        "summary": _single_line(summary)[:500],
        "cwe_id": [],
        "vulnerability_class": [],
    }


def _load_candidate(report_path: str, config: AuditConfig, repo_url: str) -> _DisclosureCandidate:
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
        _single_line(finding.get("title"))
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


def _filter_discovered_duplicates(
    stage5_reports: list[str],
    config: AuditConfig,
    repo_url: str,
    discovered_path: str,
) -> list[_DisclosureCandidate]:
    existing_keys = read_discovered_keys(discovered_path)
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


def _extract_json_object(text: str) -> str | None:
    """Extract the first JSON object from text that may contain prefixes or suffixes."""
    stripped = text.strip().removeprefix("```json").removesuffix("```").strip()
    # Try direct parse first
    try:
        json.loads(stripped)
        return stripped
    except (json.JSONDecodeError, ValueError):
        pass

    # Find the first '{' and its matching '}'
    start = stripped.find("{")
    if start == -1:
        return None

    depth = 0
    for i, ch in enumerate(stripped[start:], start=start):
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                candidate = stripped[start : i + 1]
                try:
                    json.loads(candidate)
                    return candidate
                except (json.JSONDecodeError, ValueError):
                    continue
    return None


async def _filter_semantic_duplicates(
    candidates: list[_DisclosureCandidate],
    discovered_path: str,
    config: AuditConfig,
) -> list[_DisclosureCandidate]:
    """Use an LLM agent to compare candidates against existing HTML entries for semantic duplication."""
    existing_entries = read_discovered_entries(discovered_path)
    if not existing_entries:
        return candidates

    logger.info(
        "Stage 6: Running semantic deduplication against %d existing entries.",
        len(existing_entries),
    )

    existing_text = "\n\n".join(
        (
            f"Entry {i + 1}\n"
            f"- dedupe_key: {entry.get('dedupe_key', '')}\n"
            f"- title: {entry.get('title', '')}\n"
            f"- location: {entry.get('location', '')}\n"
            f"- cwe: {entry.get('cwe', '')}\n"
            f"- vulnerability_class: {entry.get('vulnerability_class', '')}\n"
            f"- trigger: {entry.get('trigger', '')}\n"
            f"- summary: {entry.get('summary', '')}"
        )
        for i, entry in enumerate(existing_entries)
    )

    filtered: list[_DisclosureCandidate] = []
    for candidate in candidates:
        label = _candidate_label(candidate)
        prompt = load_prompt("stage6_dedupe.md", {
            "candidate_title": candidate.title,
            "candidate_location": _single_line(candidate.finding.get("location")),
            "candidate_cwe": ", ".join(_display_list(candidate.finding.get("cwe_id") or candidate.finding.get("cwe"))),
            "candidate_vuln_class": ", ".join(_display_list(candidate.finding.get("vulnerability_class"))),
            "candidate_trigger": _single_line(candidate.finding.get("trigger")),
            "candidate_summary": _single_line(candidate.finding.get("summary") or candidate.finding.get("description")),
            "existing_entries": existing_text,
        })

        log_file = os.path.join(
            config.output_dir, "stage6-disclosures", ".dedupe-logs", f"{candidate.vuln_id or 'unknown'}.log"
        )
        try:
            result = await run_agent(
                prompt,
                config,
                cwd=config.target,
                max_turns=_MAX_DEDUPE_TURNS,
                effort=_DEFAULT_DEDUPE_EFFORT,
                log_file=log_file,
            )
            json_text = _extract_json_object(result)
            if json_text is None:
                raise json.JSONDecodeError("No JSON object found in response", result, 0)
            parsed = json.loads(json_text)
            decision = str(parsed.get("decision", "")).lower()
            matched_key = str(parsed.get("matched_dedupe_key", ""))
            reason = str(parsed.get("reason", ""))

            if decision == "duplicate" and matched_key:
                logger.info(
                    "Stage 6: Semantic dedupe filtered %s as duplicate of %s. Reason: %s",
                    label,
                    matched_key,
                    reason,
                )
                continue
        except (json.JSONDecodeError, KeyError, ValueError) as exc:
            logger.warning(
                "Stage 6: Could not parse semantic dedupe response for %s: %s. Treating as new.",
                label,
                exc,
            )
        except Exception as exc:
            logger.warning(
                "Stage 6: Semantic dedupe agent failed for %s: %s. Treating as new.",
                label,
                exc,
            )

        filtered.append(candidate)

    logger.info(
        "Stage 6: Semantic dedupe kept %d/%d candidates.",
        len(filtered),
        len(candidates),
    )
    return filtered


def _existing_artifact(disclosure_report: str, filename: str) -> str | None:
    path = Path(disclosure_report).parent / filename
    return str(path) if path.exists() else None


def _extract_email_subject(email_path: str | None) -> str | None:
    """Extract the Subject line from a disclosure email.txt.

    Handles both standard RFC 822 folded headers (continuation lines start
    with whitespace) and LLM-generated subjects wrapped by ``fold -s -w 72``
    where continuation lines do not start with whitespace.
    """
    if not email_path:
        return None
    try:
        content = Path(email_path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    lines = content.splitlines()
    for i, line in enumerate(lines):
        if line.lower().startswith("subject:"):
            parts = [line.split(":", 1)[1].strip()]
            for next_line in lines[i + 1 :]:
                if not next_line.strip():
                    break
                if next_line[0] in " \t":
                    parts.append(next_line.strip())
                    continue
                # Heuristic: a new header line looks like "Header-Name: value".
                # Stop collecting if we see one; otherwise treat as wrapped
                # subject text produced by ``fold -s -w 72``.
                if re.match(r"^[A-Za-z-]+:\s", next_line):
                    break
                parts.append(next_line.strip())
            return " ".join(parts)
    return None


def _append_discovered_entries(
    successes: list[tuple[_DisclosureCandidate, str]],
    repo_snapshot: dict[str, str],
    discovered_path: str,
) -> None:
    if not successes:
        return

    latest_keys = read_discovered_keys(discovered_path)
    entries: list[str] = []
    for candidate, disclosure_report in successes:
        if candidate.dedupe_key in latest_keys:
            logger.info(
                "Stage 6: Not recording %s because it was already added to %s.",
                _candidate_label(candidate),
                discovered_path,
            )
            continue

        email_path = _existing_artifact(disclosure_report, "email.txt")
        email_title = _extract_email_subject(email_path)
        if not email_title:
            logger.warning(
                "Stage 6: Skipping %s because disclosure email subject is missing."
                " The bug reproducing process is broken.",
                _candidate_label(candidate),
            )
            continue

        entries.append(
            build_discovered_entry(
                candidate.finding,
                repo_snapshot,
                discovered_path=discovered_path,
                stage4_finding_path=candidate.finding_path,
                stage5_report_path=candidate.report_path,
                stage6_report_path=disclosure_report,
                stage6_email_path=email_path,
                stage6_zip_path=_existing_artifact(disclosure_report, "disclosure.zip"),
                stage6_email_title=email_title,
            )
        )
        latest_keys.add(candidate.dedupe_key)

    append_entries(discovered_path, entries)


def _filter_reproduced(stage5_reports: list[str]) -> list[str]:
    """Keep only Stage 5 reports from successful reproductions."""
    reproduced: list[str] = []
    for report_path in stage5_reports:
        report_dir = Path(report_path).parent
        if report_dir.name.endswith("_fp"):
            logger.info("Stage 6: Skipping false-positive Stage 5 report: %s", report_path)
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
        logger.warning("Stage 6: Cannot extract vuln ID from %s, skipping.", report_path)
        return None

    key = _task_key(vuln_id)
    stage6_vuln_dir = os.path.join(config.output_dir, "stage6-disclosures", vuln_id)
    disclosure_dir = os.path.join(stage6_vuln_dir, "disclosure")
    disclosure_report = os.path.join(disclosure_dir, "report.md")

    if checkpoint.is_complete(key):
        logger.info("Stage 6: %s already complete, skipping.", vuln_id)
        return disclosure_report if os.path.exists(disclosure_report) else None

    logger.info("Stage 6: Starting disclosure preparation for %s.", vuln_id)
    os.makedirs(disclosure_dir, exist_ok=True)

    # Locate inputs
    poc_dir = str(Path(report_path).parent)
    finding_file = _find_finding_file(vuln_id, config.output_dir)

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

    prompt = load_prompt("stage6.md", {
        "vuln_report_path": report_path,
        "poc_dir": poc_dir,
        "finding_reference": finding_reference,
        "target_path": config.target,
        "disclosure_dir": disclosure_dir,
        "vuln_id": vuln_id,
        "wiki_context": build_wiki_context(config, stage=6),
    })

    log_file = os.path.join(stage6_vuln_dir, "agent.log")
    timeout_seconds = config.agent_timeout_seconds
    if timeout_seconds is None:
        logger.info("Stage 6: Agent timeout disabled for %s.", vuln_id)

    timed_out = False
    task = asyncio.create_task(
        run_agent(
            prompt,
            config,
            cwd=config.target,
            max_turns=_MAX_TURNS,
            model=select_poc_model(config),
            effort=_DEFAULT_EFFORT,
            log_file=log_file,
        )
    )
    done, _ = await asyncio.wait({task}, timeout=timeout_seconds)

    if not done:
        if timeout_seconds is None:
            raise AssertionError("Stage 6 timed out without a configured timeout.")
        timeout_minutes = timeout_seconds // 60
        timed_out = True
        task.cancel()
        grace_done, _ = await asyncio.wait({task}, timeout=30)
        if not grace_done:
            logger.warning("Stage 6: %s agent task did not exit after cancel, moving on.", vuln_id)
        logger.warning(
            "Stage 6: %s timed out after %d minutes.",
            vuln_id, timeout_minutes,
        )
    else:
        exc = task.exception()
        if exc is not None:
            raise exc

    checkpoint.mark_complete(key)

    has_report = os.path.exists(disclosure_report)
    logger.info("Stage 6: %s complete (report=%s, timed_out=%s)", vuln_id, has_report, timed_out)
    return disclosure_report if has_report else None


async def run_stage6(
    stage5_reports: list[str],
    config: AuditConfig,
    checkpoint: CheckpointManager,
) -> list[str]:
    """Prepare disclosure artifacts for each reproduced vulnerability in parallel."""
    reproduced = _filter_reproduced(stage5_reports)
    if not reproduced:
        logger.info("Stage 6: No reproduced vulnerabilities to prepare disclosures for.")
        return []

    repo_snapshot = collect_repo_snapshot(config.target)
    repo_snapshot["llm_backend"] = config.backend
    repo_snapshot["llm_model"] = select_poc_model(config)
    repo_url = repo_snapshot.get("repo_url", "")
    discovered_path = resolve_discovered_path(config)
    candidates = _filter_discovered_duplicates(
        reproduced,
        config,
        repo_url,
        discovered_path,
    )
    if not candidates:
        logger.info(
            "Stage 6: No new reproduced vulnerabilities to prepare disclosures for after discovered-bug dedupe."
        )
        return []

    candidates = await _filter_semantic_duplicates(
        candidates,
        discovered_path,
        config,
    )
    if not candidates:
        logger.info(
            "Stage 6: No new reproduced vulnerabilities to prepare disclosures for after semantic dedupe."
        )
        return []

    logger.info("Stage 6: Preparing disclosures for %d reproduced vulnerabilities.", len(candidates))

    results = await run_parallel_limited(
        candidates,
        config.max_parallel,
        lambda candidate, _: _run_disclosure(candidate.report_path, config, checkpoint),
    )

    disclosure_reports: list[str] = []
    successful_disclosures: list[tuple[_DisclosureCandidate, str]] = []
    for i, (status, value, error) in enumerate(results):
        if i >= len(candidates):
            continue
        if status == "rejected":
            logger.error("Stage 6: %s failed: %s", os.path.basename(candidates[i].report_path), error)
            continue
        if value:
            disclosure_reports.append(value)
            successful_disclosures.append((candidates[i], value))

    _append_discovered_entries(successful_disclosures, repo_snapshot, discovered_path)

    logger.info(
        "Stage 6 complete. %d disclosure packages prepared (from %d reproduced vulnerabilities).",
        len(disclosure_reports), len(candidates),
    )
    return disclosure_reports
