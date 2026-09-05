"""Evidence-bounded recovery of missing Disclosure PoCs.

This maintenance command deliberately starts from database Disclosure rows,
copies their exact Stage 4 finding into a separate recovery output, and reruns
Stage 5/6 at the audited Git commit.  A Disclosure is updated only after the
normal retained-artifact validators accept a genuinely reproduced PoC.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from .checkpoint import CheckpointManager
from .config import AuditConfig, sandbox_mode_flags
from .db import (
    DEFAULT_DB_PATH,
    RUN_DONE,
    RUN_FAILED,
    RUN_KIND_MAINTENANCE,
    AuditStore,
)
from .disclosures import build_dedupe_key
from .logger import configure_logging, get_logger
from .repos import capture_repo_identity
from .stages.stage5 import _run_reproduce
from .stages.stage6 import _run_disclosure
from .web.settings import DEFAULT_SETTINGS_PATH, WebSettings, load_web_settings

logger = get_logger("poc_backfill")

_COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
_SKIPPED_REVIEW_STATUSES = {"duplicated", "rejected", "slop"}
_PROVIDER_BLOCKER_MARKERS = (
    "failed to authenticate",
    "authentication_error",
    "invalid api key",
    "insufficient_quota",
    "quota exceeded",
    "usage limit",
    "at capacity",
    "try a different model",
)


def _is_nonfatal_cleanup_error(exc: Exception) -> bool:
    """Recognize Docker teardown races after a task wrote its report."""
    message = str(exc).casefold()
    return (
        "cannot remove sandbox container" in message
        and "already in progress" in message
    )


class BackfillProviderUnavailable(RuntimeError):
    """Stop the batch when every subsequent agent call would also fail."""


@dataclass(frozen=True)
class BackfillCandidate:
    project: str
    dedupe_key: str
    title: str
    review_status: str
    previous_poc_status: str
    vuln_id: str
    finding_path: str
    target: str
    source_output_dir: str
    commit: str
    repo_url: str


def _load_finding(path: str) -> dict[str, Any]:
    try:
        value = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot read Stage 4 finding {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise ValueError(f"Stage 4 finding is not a JSON object: {path}")
    return value


def _latest_poc_status(
    conn: sqlite3.Connection, dedupe_key: str
) -> str:
    row = conn.execute(
        """
        SELECT p.status
        FROM vulnerabilities v
        JOIN pocs p ON p.run_id = v.run_id AND p.vuln_id = v.vuln_id
        WHERE v.dedupe_key = ?
        ORDER BY p.run_id DESC
        LIMIT 1
        """,
        (dedupe_key,),
    ).fetchone()
    return str(row[0] or "") if row else ""


def _source_run(
    conn: sqlite3.Connection, output_dir: str, commit: str
) -> sqlite3.Row | None:
    return conn.execute(
        """
        SELECT target, output_dir, repo_url, "commit"
        FROM runs
        WHERE output_dir = ?
        ORDER BY CASE WHEN "commit" = ? THEN 0 ELSE 1 END, id DESC
        LIMIT 1
        """,
        (output_dir, commit),
    ).fetchone()


def _registered_poc_report(
    conn: sqlite3.Connection, poc: dict[str, Any] | None
) -> str:
    """Return a live Stage 5 report path, or an empty string.

    Older imported history may contain a reproduced ``pocs`` row whose
    report was cleaned up (or whose path was never recorded).  Such a row is
    not enough to suppress recovery: the Terminal must resolve to a real
    retained report before it counts as evidence.
    """
    if not isinstance(poc, dict):
        return ""
    report_value = poc.get("poc_report_path")
    if not isinstance(report_value, str) or not report_value or "\x00" in report_value:
        return ""
    try:
        run_id = int(poc.get("run_id"))
    except (TypeError, ValueError):
        return ""
    row = conn.execute(
        "SELECT output_dir FROM runs WHERE id = ?", (run_id,)
    ).fetchone()
    if row is None:
        return ""
    output_dir = os.path.realpath(os.path.expanduser(str(row["output_dir"] or "")))
    if not output_dir or not os.path.isdir(output_dir):
        return ""
    report_path = os.path.realpath(
        report_value
        if os.path.isabs(report_value)
        else os.path.join(output_dir, report_value)
    )
    if not report_path.startswith(output_dir + os.sep):
        return ""
    report = Path(report_path)
    if (
        report.name != "report.md"
        or report.parent.parent.name != "stage5-pocs"
        or report.parent.name.endswith("_fp")
        or re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]{0,63}", report.parent.name) is None
    ):
        return ""
    return report_path if os.path.isfile(report_path) else ""


def _git_has_commit(target: str, commit: str) -> bool:
    result = subprocess.run(
        ["git", "-C", target, "cat-file", "-e", f"{commit}^{{commit}}"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    return result.returncode == 0


def _provider_is_unavailable(exc: Exception) -> bool:
    message = str(exc).casefold()
    return any(marker in message for marker in _PROVIDER_BLOCKER_MARKERS)


def discover_candidates(
    store: AuditStore,
    *,
    projects: set[str] | None = None,
    dedupe_keys: set[str] | None = None,
    include_nonactionable: bool = False,
) -> tuple[list[BackfillCandidate], list[dict[str, str]]]:
    """Return exact-source candidates and explicitly skipped rows."""
    candidates: list[BackfillCandidate] = []
    skipped: list[dict[str, str]] = []
    with store._connect() as conn:  # The maintenance workflow needs source-run provenance.
        for entry in store.list_disclosed():
            project = str(entry.get("project") or "")
            dedupe_key = str(entry.get("dedupe_key") or "")
            if projects and project not in projects:
                continue
            if dedupe_keys and dedupe_key not in dedupe_keys:
                continue
            if entry.get("terminal") is not None:
                continue
            # A legacy reproduced row can survive without its report after
            # retention/cleanup.  Treat that as missing evidence and allow a
            # fresh, commit-pinned recovery instead of rendering a dead
            # Terminal link or silently skipping the candidate.
            if _registered_poc_report(conn, entry.get("poc")):
                continue

            stage4 = next(
                (
                    artifact
                    for artifact in entry.get("artifacts") or []
                    if artifact.get("label") == "Stage 4 Finding"
                ),
                None,
            )
            if stage4 is None:
                skipped.append(
                    {
                        "project": project,
                        "dedupe_key": dedupe_key,
                        "title": str(entry.get("title") or ""),
                        "reason": "missing registered Stage 4 finding",
                    }
                )
                continue
            artifact = store.get_disclosed_artifact(
                project, dedupe_key, int(stage4["index"])
            )
            finding_path = str((artifact or {}).get("path") or "")
            try:
                finding = _load_finding(finding_path)
            except ValueError as exc:
                skipped.append(
                    {
                        "project": project,
                        "dedupe_key": dedupe_key,
                        "title": str(entry.get("title") or ""),
                        "reason": str(exc),
                    }
                )
                continue
            if build_dedupe_key(finding, entry.get("repo_url")) != dedupe_key:
                skipped.append(
                    {
                        "project": project,
                        "dedupe_key": dedupe_key,
                        "title": str(entry.get("title") or ""),
                        "reason": "Stage 4 finding no longer matches the Disclosure key",
                    }
                )
                continue

            review_status = str(entry.get("review_status") or "unreviewed")
            previous_status = _latest_poc_status(conn, dedupe_key)
            if not include_nonactionable and (
                review_status in _SKIPPED_REVIEW_STATUSES
                or previous_status == "false-positive"
            ):
                reason = (
                    f"review status is {review_status}"
                    if review_status in _SKIPPED_REVIEW_STATUSES
                    else "latest reproduction status is false-positive"
                )
                skipped.append(
                    {
                        "project": project,
                        "dedupe_key": dedupe_key,
                        "title": str(entry.get("title") or ""),
                        "reason": reason,
                    }
                )
                continue

            commit = str(entry.get("audited_commit") or "").lower()
            vuln_id = str(finding.get("id") or "")
            source_output = str(Path(finding_path).parent.parent.resolve())
            source_run = _source_run(conn, source_output, commit)
            if (
                not _COMMIT_RE.fullmatch(commit)
                or not vuln_id
                or source_run is None
            ):
                skipped.append(
                    {
                        "project": project,
                        "dedupe_key": dedupe_key,
                        "title": str(entry.get("title") or ""),
                        "reason": "incomplete historical run provenance",
                    }
                )
                continue
            target = os.path.realpath(str(source_run["target"] or ""))
            if not os.path.isdir(target) or not _git_has_commit(target, commit):
                skipped.append(
                    {
                        "project": project,
                        "dedupe_key": dedupe_key,
                        "title": str(entry.get("title") or ""),
                        "reason": "audited Git commit is unavailable in the source mirror",
                    }
                )
                continue

            candidates.append(
                BackfillCandidate(
                    project=project,
                    dedupe_key=dedupe_key,
                    title=str(entry.get("title") or vuln_id),
                    review_status=review_status,
                    previous_poc_status=previous_status,
                    vuln_id=vuln_id,
                    finding_path=finding_path,
                    target=target,
                    source_output_dir=source_output,
                    commit=commit,
                    # The historical catalogue URL is part of the stable
                    # dedupe payload.  Do not replace it with a later run's
                    # spelling (for example, adding a trailing ``.git``).
                    repo_url=str(entry.get("repo_url") or source_run["repo_url"] or ""),
                )
            )

    priority = {"confirmed": 0, "reported": 1, "bug": 2, "unreviewed": 3}
    candidates.sort(
        key=lambda item: (
            priority.get(item.review_status, 9),
            item.project.casefold(),
            item.commit,
            item.vuln_id,
        )
    )
    return candidates, skipped


def _recovery_output(settings: WebSettings, candidate: BackfillCandidate) -> str:
    base = os.path.join(
        settings.results_dir,
        candidate.project,
        f"audit-output-{candidate.commit[:12]}-poc-backfill",
    )
    # A previous maintenance run may have left a complete (or partially
    # complete) tree for the same audited commit.  Reusing it would make the
    # subsequent ``persist_artifacts`` scan attribute the old run's Stage 4/5
    # files to the new run.  Keep the first stable path for compatibility, but
    # isolate every retry in a deterministic sibling directory.
    if not os.path.exists(base):
        return base
    for attempt in range(2, 1000):
        retry = f"{base}-retry-{attempt}"
        if not os.path.exists(retry):
            return retry
    raise RuntimeError(f"too many PoC backfill retries for {base}")


def _build_config(
    settings: WebSettings,
    candidate: BackfillCandidate,
    output_dir: str,
    backend: str | None = None,
    model: str | None = None,
) -> AuditConfig:
    selected_backend = backend or settings.backend
    provider = settings.provider(selected_backend)
    sandbox_enabled, sandbox_network_enabled = sandbox_mode_flags(
        settings.sandbox_mode
    )
    return AuditConfig(
        target=candidate.target,
        output_dir=output_dir,
        max_parallel=1,
        resume=True,
        update_repo=False,
        log_level=settings.log_level,
        backend=selected_backend,  # type: ignore[arg-type]
        model=model or provider.model or None,
        provider_mode=provider.mode,
        provider_base_url=provider.base_url or None,
        provider_api_key=provider.api_key or None,
        sandbox_enabled=sandbox_enabled,
        sandbox_network_enabled=sandbox_network_enabled,
        poc_source_commit=candidate.commit,
    )


def _pin_run_identity(
    store: AuditStore, run_id: int, candidate: BackfillCandidate
) -> None:
    identity = capture_repo_identity(candidate.target)
    identity["commit"] = candidate.commit
    identity["dirty"] = False
    identity["repo_url"] = candidate.repo_url
    store.set_run_identity(run_id, identity)


def _copy_finding(candidate: BackfillCandidate, output_dir: str) -> str:
    _load_finding(candidate.finding_path)
    destination = (
        Path(output_dir) / "stage4-vulnerabilities" / f"{candidate.vuln_id}.json"
    )
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        existing = _load_finding(str(destination))
        if build_dedupe_key(existing, candidate.repo_url) != candidate.dedupe_key:
            raise ValueError(
                f"recovery ID collision at {destination}: dedupe key differs"
            )
        return str(destination)
    shutil.copyfile(candidate.finding_path, destination)
    return str(destination)


async def _run_group(
    store: AuditStore,
    settings: WebSettings,
    candidates: list[BackfillCandidate],
    *,
    backend: str | None = None,
    model: str | None = None,
) -> list[dict[str, Any]]:
    first = candidates[0]
    output_dir = _recovery_output(settings, first)
    config = _build_config(settings, first, output_dir, backend, model)
    started_at = time.time()
    run_id = store.create_run(
        config,
        started_at=started_at,
        run_kind=RUN_KIND_MAINTENANCE,
    )
    _pin_run_identity(store, run_id, first)
    checkpoint = CheckpointManager(output_dir, resume=True)
    results: list[dict[str, Any]] = []
    errors: list[str] = []
    warnings: list[str] = []
    provider_unavailable = False
    try:
        for candidate in candidates:
            result: dict[str, Any] = {
                **asdict(candidate),
                "run_id": run_id,
                "recovery_output_dir": output_dir,
                "result": "error",
            }
            try:
                finding_path = _copy_finding(candidate, output_dir)
                logger.info(
                    "Backfill: rerunning %s %s at %s (%s)",
                    candidate.project,
                    candidate.vuln_id,
                    candidate.commit[:12],
                    candidate.title,
                )
                stage5_report = await _run_reproduce(
                    finding_path, config, checkpoint
                )
                store.persist_artifacts(run_id, output_dir)
                if stage5_report is None:
                    result["result"] = "not-reproduced"
                    results.append(result)
                    continue

                stage6_report = await _run_disclosure(
                    stage5_report, config, checkpoint
                )
                store.persist_artifacts(run_id, output_dir)
                terminal = store.get_disclosed_terminal_candidate(
                    candidate.project, candidate.dedupe_key
                )
                if stage6_report is None or terminal is None:
                    raise RuntimeError(
                        "reproduced Stage 5 result did not yield a registered Stage 6 terminal"
                    )
                result["result"] = "reproduced"
                result["stage5_report"] = stage5_report
                result["stage6_report"] = stage6_report
            except Exception as exc:
                message = f"{candidate.project}/{candidate.vuln_id}: {exc}"
                logger.exception("Backfill failed for %s", message)
                if _is_nonfatal_cleanup_error(exc):
                    # The agent has already exported a report; Docker's
                    # asynchronous ``--rm`` teardown is not a PoC failure.
                    result["result"] = "not-reproduced"
                    result["warning"] = str(exc)
                    warnings.append(message)
                else:
                    errors.append(message)
                    result["error"] = str(exc)
                if _provider_is_unavailable(exc):
                    results.append(result)
                    provider_unavailable = True
                    raise BackfillProviderUnavailable(message) from exc
            results.append(result)
    finally:
        status = (
            RUN_FAILED
            if provider_unavailable or (errors and len(errors) == len(candidates))
            else RUN_DONE
        )
        store.finish_run(
            run_id,
            status,
            error="\n".join(errors),
            backends_used=config.backends_used,
            models_used=config.models_used,
            usage_stats=config.usage_stats,
            warning="\n".join(warnings),
        )
        summary_path = Path(output_dir) / "poc-backfill-summary.json"
        summary_path.write_text(
            json.dumps(
                {
                    "run_id": run_id,
                    "started_at": started_at,
                    "finished_at": time.time(),
                    "results": results,
                },
                ensure_ascii=False,
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
    return results


async def run_backfill(
    store: AuditStore,
    settings: WebSettings,
    candidates: list[BackfillCandidate],
    *,
    backend: str | None = None,
    model: str | None = None,
) -> list[dict[str, Any]]:
    grouped: dict[tuple[str, str, str], list[BackfillCandidate]] = {}
    for candidate in candidates:
        grouped.setdefault(
            (candidate.project, candidate.commit, candidate.target), []
        ).append(candidate)

    results: list[dict[str, Any]] = []
    for group in grouped.values():
        ids = [candidate.vuln_id for candidate in group]
        if len(ids) != len(set(ids)):
            raise ValueError(
                f"recovery group has colliding vulnerability IDs: {ids}"
            )
        results.extend(
            await _run_group(
                store, settings, group, backend=backend, model=model
            )
        )
    return results


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Rerun missing Disclosure PoCs at their audited commits."
    )
    parser.add_argument("--db", default=DEFAULT_DB_PATH)
    parser.add_argument("--settings", default=DEFAULT_SETTINGS_PATH)
    parser.add_argument("--project", action="append", default=[])
    parser.add_argument("--dedupe-key", action="append", default=[])
    parser.add_argument("--limit", type=int, default=0)
    parser.add_argument("--include-nonactionable", action="store_true")
    parser.add_argument("--backend", choices=("claude", "codex"))
    parser.add_argument(
        "--model",
        help="Override the selected provider model for this maintenance run only.",
    )
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--log-level", default="INFO")
    return parser


def main() -> None:
    args = _build_parser().parse_args()
    configure_logging(args.log_level)
    store = AuditStore(args.db)
    settings = load_web_settings(args.settings)
    candidates, skipped = discover_candidates(
        store,
        projects=set(args.project) or None,
        dedupe_keys=set(args.dedupe_key) or None,
        include_nonactionable=args.include_nonactionable,
    )
    if args.limit < 0:
        raise SystemExit("--limit must be non-negative")
    if args.limit:
        candidates = candidates[: args.limit]
    plan = {
        "candidate_count": len(candidates),
        "skipped_count": len(skipped),
        "candidates": [asdict(candidate) for candidate in candidates],
        "skipped": skipped,
    }
    if args.dry_run:
        print(json.dumps(plan, ensure_ascii=False, indent=2))
        return
    if not candidates:
        print(json.dumps(plan, ensure_ascii=False, indent=2))
        return
    try:
        results = asyncio.run(
            run_backfill(
                store,
                settings,
                candidates,
                backend=args.backend,
                model=args.model,
            )
        )
    except BackfillProviderUnavailable as exc:
        logger.error("PoC backfill stopped because the provider is unavailable: %s", exc)
        raise SystemExit(2) from None
    except KeyboardInterrupt:
        print("Interrupted.", file=sys.stderr)
        raise SystemExit(130) from None
    print(
        json.dumps(
            {**plan, "results": results}, ensure_ascii=False, indent=2
        )
    )


if __name__ == "__main__":
    main()
