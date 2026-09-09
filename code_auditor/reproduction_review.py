from __future__ import annotations

import json
import os
import shutil
import stat
from pathlib import Path
from typing import Any

from .agent import run_agent
from .config import AuditConfig, select_poc_model
from .prompts import load_prompt
from .retention import (
    export_retained_artifacts,
    load_retain_manifest,
    secure_generated_manifest_mode,
)
from .sandbox import DockerScratch
from .validation.stage6 import validate_stage6_disclosure

_DISPOSITIONS = {
    "still-vulnerable",
    "likely-fixed",
    "harness-stale",
    "environment-blocked",
    "false-positive-possible",
    "unknown",
}
_OUTCOMES = {"reproduced", "not-reproduced", "inconclusive", "error"}
_MAX_REVIEW_FILE_BYTES = 4 * 1024 * 1024


def _load_assessment(path: Path, expected_outcome: str) -> dict[str, Any]:
    if not path.is_file() or path.is_symlink():
        raise ValueError("reproduction review did not produce assessment.json")
    if path.stat().st_size > _MAX_REVIEW_FILE_BYTES:
        raise ValueError("reproduction assessment exceeds the size limit")
    try:
        assessment = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"invalid reproduction assessment: {exc}") from exc
    if not isinstance(assessment, dict) or assessment.get("schema_version") != 1:
        raise ValueError("reproduction assessment must use schema_version 1")
    if assessment.get("outcome") != expected_outcome:
        raise ValueError(
            "Agent assessment outcome does not match the recorded PoC result"
        )
    if assessment.get("disposition") not in _DISPOSITIONS:
        raise ValueError("Agent assessment has an unsupported disposition")
    for field in ("summary", "source_analysis", "disclosure_update"):
        value = assessment.get(field)
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"Agent assessment is missing {field}")
    return assessment


def _copy_regular(source: Path, destination: Path) -> None:
    info = source.lstat()
    if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode):
        raise ValueError(f"review output must be a regular file: {source.name}")
    if info.st_size > _MAX_REVIEW_FILE_BYTES:
        raise ValueError(f"review output exceeds size limit: {source.name}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, destination, follow_symlinks=False)
    os.chmod(destination, 0o600)


async def run_reproduction_review(
    config: AuditConfig,
    *,
    candidate: dict[str, Any],
    result_path: str,
    retest_report_path: str,
    finding_path: str,
    outcome: str,
) -> dict[str, Any]:
    """Analyze one pinned latest-source retest and prepare a local update draft."""
    if outcome not in _OUTCOMES:
        raise ValueError(f"unsupported reproduction outcome: {outcome}")

    persistent_dir = Path(config.output_dir, "reproduction-review")
    persistent_dir.mkdir(parents=True, exist_ok=True)
    sandbox: DockerScratch | None = None
    work_config = config
    work_result = Path(result_path)
    work_retest = Path(retest_report_path)
    work_finding = Path(finding_path)
    previous_dir = candidate.get("reference_dir") or ""
    work_previous = Path(previous_dir) if previous_dir else None

    if config.sandbox_enabled:
        sandbox = DockerScratch(config, f"reproduction-review-{candidate['vuln_id']}")
        try:
            await sandbox.prepare(config.target, config.poc_source_commit or "")
            work_config = sandbox.audit_config(config)
            work_result = sandbox.copy_input(result_path, "reproduction-result.json")
            work_retest_dir = sandbox.copy_input_tree(
                str(Path(retest_report_path).parent), "latest-retest"
            )
            work_retest = work_retest_dir / Path(retest_report_path).name
            work_finding = sandbox.copy_input(finding_path, "finding.json")
            if previous_dir:
                work_previous = sandbox.copy_input_tree(
                    previous_dir, "previous-disclosure"
                )
        except Exception:
            await sandbox.close()
            raise

    work_dir = Path(work_config.output_dir, "reproduction-review")
    work_dir.mkdir(parents=True, exist_ok=True)
    prompt = load_prompt(
        "reproduction_review.md",
        {
            "finding_path": str(work_finding),
            "result_path": str(work_result),
            "retest_report_path": str(work_retest),
            "previous_disclosure_path": str(work_previous)
            if work_previous
            else "not available",
            "target_path": work_config.poc_worktree or work_config.target,
            "output_dir": str(work_dir),
            "project": str(candidate.get("project") or ""),
            "title": str(candidate.get("title") or candidate.get("vuln_id") or ""),
            "base_commit": str(
                candidate.get("audited_commit") or candidate.get("commit") or "unknown"
            ),
            "tested_commit": str(config.poc_source_commit or ""),
            "outcome": outcome,
        },
    )

    task_error: BaseException | None = None
    try:
        await run_agent(
            prompt,
            work_config,
            cwd=work_config.poc_worktree or work_config.target,
            max_turns=120,
            model=select_poc_model(config),
            effort="medium",
            log_file=str(work_dir / "agent.log"),
            sandbox=sandbox,
        )
        assessment = _load_assessment(work_dir / "assessment.json", outcome)
        report = work_dir / "retest-report.md"
        try:
            report_info = report.lstat()
        except OSError as exc:
            raise ValueError(
                "reproduction review did not produce retest-report.md"
            ) from exc
        if (
            not stat.S_ISREG(report_info.st_mode)
            or stat.S_ISLNK(report_info.st_mode)
            or report_info.st_size > _MAX_REVIEW_FILE_BYTES
        ):
            raise ValueError("reproduction review did not produce retest-report.md")
        try:
            report_text = report.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as exc:
            raise ValueError(
                "reproduction review produced an invalid retest-report.md"
            ) from exc
        if not report_text.strip():
            raise ValueError("reproduction review did not produce retest-report.md")

        if sandbox is not None:
            _copy_regular(
                work_dir / "assessment.json", persistent_dir / "assessment.json"
            )
            _copy_regular(report, persistent_dir / "retest-report.md")

        draft_dir = work_dir / "disclosure-draft"
        persistent_draft = persistent_dir / "disclosure-draft"
        if outcome == "reproduced":
            if not draft_dir.is_dir():
                raise ValueError(
                    "successful latest-source reproduction has no disclosure draft"
                )
            issues = validate_stage6_disclosure(str(draft_dir))
            if issues:
                raise ValueError(
                    "invalid refreshed disclosure draft: "
                    + "; ".join(issue.description for issue in issues)
                )
            secure_generated_manifest_mode(str(draft_dir))
            load_retain_manifest(
                str(draft_dir),
                required_paths=(
                    "report.md",
                    "email.txt",
                    "disclosure.zip",
                    "reproduce.sh",
                ),
                max_file_bytes=config.retain_max_file_bytes,
                max_total_bytes=config.retain_max_total_bytes,
            )
            # Normalize both Docker and local-worktree output through the
            # bounded retain manifest.  In local mode source and destination
            # are the same directory; the exporter still atomically replaces
            # it with only the registered regular files.
            export_retained_artifacts(
                str(draft_dir),
                str(persistent_draft),
                required_paths=(
                    "report.md",
                    "email.txt",
                    "disclosure.zip",
                    "reproduce.sh",
                ),
                max_file_bytes=config.retain_max_file_bytes,
                max_total_bytes=config.retain_max_total_bytes,
            )
            issues = validate_stage6_disclosure(str(persistent_draft))
            if issues:
                raise ValueError(
                    "invalid retained disclosure draft: "
                    + "; ".join(issue.description for issue in issues)
                )

        return {
            **assessment,
            "assessment_path": str(persistent_dir / "assessment.json"),
            "retest_report_path": str(persistent_dir / "retest-report.md"),
            "draft_path": str(persistent_draft) if outcome == "reproduced" else "",
        }
    except BaseException as exc:
        task_error = exc
        raise
    finally:
        if sandbox is not None:
            try:
                await sandbox.close()
            except Exception:
                if task_error is None:
                    raise
