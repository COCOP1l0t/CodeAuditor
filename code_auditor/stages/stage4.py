from __future__ import annotations

import json
import os
import re
import shutil
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path

from ..agent import run_agent
from ..checkpoint import CheckpointManager
from ..config import AuditConfig
from ..contracts import read_json_object
from ..cvss import severity as cvss_severity
from ..disclosures import build_dedupe_key
from ..layout import checkpoint_key, stage4_paths
from ..logger import get_logger
from ..prompts import load_prompt
from ..repos import capture_repo_identity
from ..semantic_dedupe import (
    candidate_from_finding,
    filter_semantic_duplicates,
    write_dedupe_report,
)
from ..stage_runtime import finalize_checkpoint, repair_until_valid
from ..utils import (
    collect_parallel_results,
    format_validation_issues,
    list_json_files,
    natural_sort_key,
    run_parallel_limited,
)
from ..validation.stage4 import validate_stage4_file
from ..wiki import build_wiki_context

logger = get_logger("stage4")

_SEVERITY_ORDER = ["Critical", "High", "Medium", "Low"]
_SEVERITY_PREFIX = {"Critical": "C", "High": "H", "Medium": "M", "Low": "L"}
_VULN_FILENAME_RE = re.compile(r"^[CHML]-\d{2,}\.json$")


def _task_key(finding_filename: str) -> str:
    return checkpoint_key(4, finding_filename)


@dataclass
class _VulnerabilityDocument:
    path: Path
    data: dict

    @classmethod
    def load(cls, path: str | Path) -> "_VulnerabilityDocument":
        return cls(path=Path(path), data=read_json_object(path))

    @property
    def vuln_id(self) -> str | None:
        value = self.data.get("id")
        return value if isinstance(value, str) and value else None

    @property
    def cvss_score(self) -> float:
        try:
            return float(self.data.get("cvss_score", 0))
        except (TypeError, ValueError):
            return 0.0

    @property
    def severity(self) -> str | None:
        value = cvss_severity(self.cvss_score)
        return None if value == "None" else value

    def set_identity(self, vuln_id: str, severity: str) -> None:
        self.data["id"] = vuln_id
        self.data["severity"] = severity

    def move_to(self, path: str | Path) -> None:
        self.path = Path(path)

    def write(self) -> None:
        self.path.write_text(
            json.dumps(self.data, indent=2) + "\n", encoding="utf-8"
        )


def _list_existing_final_files(stage4_dir: str) -> list[str]:
    files = list_json_files(stage4_dir)
    return [f for f in files if _VULN_FILENAME_RE.fullmatch(os.path.basename(f))]


def _load_existing_documents(paths: list[str]) -> list[_VulnerabilityDocument]:
    documents: list[_VulnerabilityDocument] = []
    for path in paths:
        try:
            documents.append(_VulnerabilityDocument.load(path))
        except ValueError:
            continue
    return documents


async def _run_finding(
    stage3_file_path: str,
    config: AuditConfig,
    checkpoint: CheckpointManager,
    vuln_criteria_path: str,
) -> str | None:
    stage3_filename = os.path.basename(stage3_file_path)
    key = _task_key(stage3_filename)
    paths = stage4_paths(config.output_dir)
    pending_dir = paths["pending"]
    pending_path = os.path.join(pending_dir, stage3_filename)
    log_file = os.path.join(
        paths["logs"], f"{os.path.splitext(stage3_filename)[0]}.log"
    )

    def validator():
        return validate_stage4_file(pending_path)

    async def repair(prompt: str) -> object:
        return await run_agent(
            prompt, config, cwd=config.target, max_turns=10, log_file=log_file
        )

    def repair_prompt(issues):
        return (
            f"The evaluation file at `{pending_path}` failed validation. "
            "Please fix all issues below:\n\n"
            f"```\n{format_validation_issues(issues)}\n```"
        )

    if checkpoint.is_complete(key):
        if not os.path.exists(pending_path):
            logger.info("Stage 4: %s already complete, skipping.", stage3_filename)
            return None

        issues = validator()
        if not issues:
            logger.info("Stage 4: %s already complete, skipping.", stage3_filename)
            checkpoint.mark_complete(key)
            return pending_path

        logger.warning(
            "Stage 4: Existing pending output for %s is invalid; deleting it and rerunning.\n%s",
            stage3_filename,
            format_validation_issues(issues),
        )
        with suppress(OSError):
            os.remove(pending_path)
        checkpoint.clear(key)

    logger.info("Stage 4: Starting evaluation of %s.", stage3_filename)
    prompt = load_prompt("stage4.md", {
        "finding_file_path": stage3_file_path,
        "output_path": pending_path,
        "vuln_criteria_path": vuln_criteria_path,
        "wiki_context": build_wiki_context(config, stage=4),
    })

    await run_agent(prompt, config, cwd=config.target, max_turns=100, log_file=log_file)

    confirmed = os.path.exists(pending_path)
    if confirmed:
        issues = validator()
        if issues:
            logger.warning("Stage 4: Validation failed for %s\n%s", pending_path, format_validation_issues(issues))
            issues = await repair_until_valid(
                validator=validator,
                repair=repair,
                repair_prompt=repair_prompt,
                max_attempts=1,
            )
            if issues:
                logger.warning("Stage 4: Repair failed for %s\n%s", pending_path, format_validation_issues(issues))
                with suppress(OSError):
                    os.remove(pending_path)
                checkpoint.clear(key)
                return None

    finalize_checkpoint(checkpoint, key, valid=True)
    logger.info("Stage 4: %s complete (confirmed=%s)", stage3_filename, confirmed)
    return pending_path if confirmed else None


def _dedupe_findings(
    findings: list[tuple[_VulnerabilityDocument, str, float]],
    existing_documents: list[_VulnerabilityDocument],
    repo_url: str,
) -> list[tuple[_VulnerabilityDocument, str, float]]:
    """Remove duplicate findings that describe the same vulnerability.

    ``findings`` must already be sorted by severity (Critical first) and
    CVSS descending so that the first occurrence of each dedupe_key is kept.
    """
    seen_keys: set[str] = set()

    for document in existing_documents:
        try:
            seen_keys.add(build_dedupe_key(document.data, repo_url=repo_url))
        except Exception:
            pass

    deduped: list[tuple[_VulnerabilityDocument, str, float]] = []
    for document, severity, cvss in findings:
        try:
            key = build_dedupe_key(document.data, repo_url=repo_url)
        except Exception as e:
            logger.warning(
                "Stage 4: Could not compute dedupe key for %s: %s; keeping.",
                document.path.name, e,
            )
            deduped.append((document, severity, cvss))
            continue

        if key in seen_keys:
            logger.info(
                "Stage 4: Skipping duplicate finding %s (dedupe_key=%s).",
                document.path.name, key,
            )
            with suppress(OSError):
                document.path.unlink()
            continue

        seen_keys.add(key)
        deduped.append((document, severity, cvss))

    return deduped


async def _semantic_dedupe_pending(
    pending_paths: list[str],
    config: AuditConfig,
) -> list[str]:
    """Keep one representative pending finding per semantic root cause.

    This runs before IDs are assigned and before Stage 5. Expensive PoC work is
    therefore limited to root causes that survived both exact and semantic
    deduplication. Duplicate pending files are retained under ``_duplicates``
    for auditability instead of being deleted.
    """
    if not pending_paths:
        return []

    paths = stage4_paths(config.output_dir)
    duplicates_dir = paths["duplicates"]
    log_dir = os.path.join(paths["directory"], ".semantic-dedupe-logs")
    report_path = os.path.join(paths["directory"], "semantic-dedupe.json")
    repo_url = capture_repo_identity(config.target).get("repo_url", "")

    candidates = []
    for path in pending_paths:
        try:
            document = _VulnerabilityDocument.load(path)
        except ValueError:
            logger.warning("Stage 4: Could not load pending finding for dedupe: %s", path)
            continue
        candidate = candidate_from_finding(
            os.path.basename(path),
            document.data,
            repo_url=repo_url,
            payload=path,
        )
        candidates.append(candidate)

    kept, decisions = await filter_semantic_duplicates(
        candidates,
        config.known_disclosures,
        config,
        log_dir=log_dir,
        label="Stage 4",
        run_agent_fn=run_agent,
        load_prompt_fn=load_prompt,
    )
    write_dedupe_report(report_path, decisions)

    duplicate_ids = {
        decision.candidate_id
        for decision in decisions
        if decision.decision == "duplicate"
    }
    if duplicate_ids:
        os.makedirs(duplicates_dir, exist_ok=True)
        for candidate in candidates:
            if candidate.candidate_id not in duplicate_ids:
                continue
            source = str(candidate.payload)
            destination = os.path.join(duplicates_dir, candidate.candidate_id)
            with suppress(FileNotFoundError):
                os.replace(source, destination)

    logger.info(
        "Stage 4: Semantic dedupe kept %d/%d freshly evaluated findings.",
        len(kept),
        len(pending_paths),
    )
    return [str(candidate.payload) for candidate in kept]


def _assign_ids_and_finalize(pending_paths: list[str], config: AuditConfig) -> list[str]:
    stage4_dir = stage4_paths(config.output_dir)["directory"]
    existing_final_files = _list_existing_final_files(stage4_dir)
    existing_documents = _load_existing_documents(existing_final_files)

    counters: dict[str, int] = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}

    for document in existing_documents:
        existing_id = document.vuln_id
        if not existing_id or "-" not in existing_id:
            continue
        prefix, number_text = existing_id.split("-", 1)
        for sev, sev_prefix in _SEVERITY_PREFIX.items():
            if sev_prefix == prefix:
                try:
                    counters[sev] = max(counters[sev], int(number_text))
                except ValueError:
                    logger.warning(
                        "Stage 4: Ignoring malformed existing vulnerability ID %s in %s",
                        existing_id,
                        document.path,
                    )
                break

    findings: list[tuple[_VulnerabilityDocument, str, float]] = []
    for pending_path in pending_paths:
        issues = validate_stage4_file(pending_path)
        if issues:
            logger.warning(
                "Stage 4: Skipping invalid pending output %s\n%s",
                os.path.basename(pending_path),
                format_validation_issues(issues),
            )
            continue

        document = _VulnerabilityDocument.load(pending_path)
        severity = document.severity
        if severity:
            findings.append((document, severity, document.cvss_score))
        else:
            logger.warning("Stage 4: Skipping %s because severity could not be derived from CVSS score.", os.path.basename(pending_path))

    # Sort by severity order, then by cvss_score descending (higher score -> smaller ID)
    findings.sort(key=lambda x: (_SEVERITY_ORDER.index(x[1]), -x[2]))

    repo_url = capture_repo_identity(config.target).get("repo_url", "")
    findings = _dedupe_findings(findings, existing_documents, repo_url)

    finalized: list[str] = list(existing_final_files)
    for document, severity, _cvss in findings:
        next_count = counters[severity] + 1
        counters[severity] = next_count
        real_id = f"{_SEVERITY_PREFIX[severity]}-{next_count:02d}"
        final_path = os.path.join(stage4_dir, f"{real_id}.json")
        original_name = document.path.name
        shutil.move(str(document.path), final_path)
        document.move_to(final_path)
        document.set_identity(real_id, severity)
        document.write()
        finalized.append(final_path)
        logger.info("Stage 4: Assigned %s to %s", real_id, original_name)

    finalized.sort(key=lambda a: (
        {"C": 0, "H": 1, "M": 2, "L": 3}.get(os.path.basename(a).split("-")[0], 99),
        natural_sort_key(a),
    ))
    return finalized


def _backfill_stage4_markers(
    finding_files: list[str],
    config: AuditConfig,
    checkpoint: CheckpointManager,
) -> None:
    """Create markers for findings already processed in a previous run.

    When a previous run evaluated findings but was interrupted (or predates
    marker-based tracking), pending findings may lack checkpoint markers even
    though they were already processed. Only exact pending filenames are safe
    to backfill; inferring completion from AU ordering can skip work after a
    parallel or interrupted run.
    """
    pending_dir = stage4_paths(config.output_dir)["pending"]
    if not os.path.isdir(pending_dir):
        return

    pending_files = {
        name for name in os.listdir(pending_dir)
        if os.path.isfile(os.path.join(pending_dir, name))
    }
    if not pending_files:
        return

    backfilled = 0
    for ff in finding_files:
        filename = os.path.basename(ff)
        if filename in pending_files:
            key = _task_key(filename)
            checkpoint.mark_complete(key)
            backfilled += 1

    if backfilled:
        logger.info("Stage 4: Backfilled %d markers from exact pending files.", backfilled)


async def run_stage4(
    finding_files: list[str],
    config: AuditConfig,
    checkpoint: CheckpointManager,
    vuln_criteria_path: str,
    progress: object | None = None,
) -> list[str]:
    if not finding_files:
        logger.info("Stage 4: No findings to evaluate.")
        return _list_existing_final_files(
            stage4_paths(config.output_dir)["directory"]
        )

    if config.resume:
        _backfill_stage4_markers(finding_files, config, checkpoint)

    completed = 0

    def task_complete(index: int, finding_path: str) -> None:
        nonlocal completed
        completed += 1
        if progress is not None:
            progress.update(
                items_done=completed,
                items_total=len(finding_files),
                detail=f"Evaluated {completed}/{len(finding_files)} findings",
            )

    results = await run_parallel_limited(
        finding_files,
        config.max_parallel,
        lambda ff, _: _run_finding(ff, config, checkpoint, vuln_criteria_path),
        on_complete=task_complete,
    )

    confirmed_pending = collect_parallel_results(
        results,
        finding_files,
        stage="stage4",
        config=config,
        logger=logger,
        item_id=os.path.basename,
    )

    logger.info("Stage 4: %s confirmed findings (from %s candidates).", len(confirmed_pending), len(finding_files))
    if progress is not None:
        progress.update(
            items_done=len(finding_files),
            items_total=len(finding_files),
            detail="Semantically deduplicating confirmed findings",
        )

    confirmed_pending = await _semantic_dedupe_pending(confirmed_pending, config)

    final_paths = _assign_ids_and_finalize(confirmed_pending, config)
    logger.info("Stage 4 complete. Final findings: %s", len(final_paths))
    return final_paths
