"""History-stage reconstruction for completed and imported audit runs."""

from __future__ import annotations

from pathlib import Path

from ..layout import markers_dir, stage1_paths, stage_dir
from ..stage_state import read_stage_state


def _count_json_files(base: Path, pattern: str) -> int:
    directory = base / pattern.split("/")[0]
    if not directory.is_dir():
        return 0
    return sum(1 for p in base.glob(pattern) if p.is_file())


def _run_stage_summary(run: dict) -> list[dict]:
    """Reconstruct per-stage status for a finished run from on-disk evidence.

    Live runs get stage updates from the progress reporter instead; this
    summary lets the History detail page show Stages for completed, failed,
    cancelled, and imported runs. Completion is derived from checkpoint
    markers (``.markers/``), falling back to artifact presence for runs that
    predate marker-based tracking.
    """
    base = Path(run.get("output_dir") or "")
    persisted = read_stage_state(str(base)) if base.is_dir() else {}
    if persisted:
        result = []
        for stage in range(7):
            state = persisted.get(stage, {})
            status = str(state.get("status") or "pending")
            result.append(
                {
                    "stage": stage,
                    "status": status,
                    "detail": str(state.get("detail") or ""),
                    "items_done": int(state.get("items_done") or 0),
                    "items_total": int(state.get("items_total") or 0),
                }
            )
        return result
    markers: set[str] = set()
    marker_root = Path(markers_dir(str(base)))
    if marker_root.is_dir():
        markers = {p.name for p in marker_root.iterdir() if p.is_file()}

    au_total = len(run.get("analysis_units") or [])
    findings_total = _count_json_files(base, "stage3-findings/*.json")
    vuln_total = len(run.get("vulnerabilities") or []) + len(
        run.get("poc_issues") or []
    )
    disclosures_total = int(run.get("disclosures_count") or 0)
    failed = run.get("status") == "failed"

    def entry(
        stage: int,
        done: bool,
        items_done: int = 0,
        items_total: int = 0,
        detail: str = "",
    ) -> dict:
        if done:
            status = "done"
        elif failed and items_done > 0:
            status = "failed"
        else:
            status = "pending"
        return {
            "stage": stage,
            "status": status,
            "detail": detail,
            "items_done": items_done,
            "items_total": items_total,
        }

    def marked(prefix: str, total: int, artifacts_exist: bool) -> tuple[bool, int]:
        done_count = sum(1 for name in markers if name.startswith(prefix))
        if done_count == 0 and not markers:
            # Run predates checkpoint markers: fall back to artifact presence.
            return artifacts_exist, total if artifacts_exist else 0
        return total > 0 and done_count >= total, done_count

    s3_done, s3_count = marked("stage3-", au_total, findings_total > 0)
    s4_done, s4_count = marked("stage4-", findings_total, vuln_total > 0)
    s5_done, s5_count = marked("stage5-", vuln_total, vuln_total > 0)
    stage6_root = Path(stage_dir(str(base), 6))
    disclosures_exist = stage6_root.is_dir() and any(stage6_root.iterdir())
    s6_done, s6_count = marked("stage6-", disclosures_total, disclosures_exist)

    return [
        entry(0, base.is_dir()),
        entry(
            1,
            (
                Path(stage1_paths(str(base))["record"]).is_file()
            ),
        ),
        entry(2, "stage2" in markers or au_total > 0, au_total, au_total),
        entry(3, s3_done, min(s3_count, au_total), au_total),
        entry(4, s4_done, min(s4_count, findings_total), findings_total),
        entry(5, s5_done, min(s5_count, vuln_total), vuln_total),
        entry(6, s6_done, min(s6_count, disclosures_total), disclosures_total),
    ]
