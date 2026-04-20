from __future__ import annotations

import json
import os
from dataclasses import dataclass

from ..agent import run_agent
from ..checkpoint import CheckpointManager
from ..config import AuditConfig, ValidationIssue
from ..logger import get_logger
from ..prompts import load_prompt
from ..utils import format_validation_issues
from ..validation.stage2 import (
    validate_stage2_manifest_final,
    validate_stage2_phase_a,
    validate_stage2_phase_b_entry,
)

logger = get_logger("stage2")


_PHASE_A_TASK_KEY = "stage2:research"
_PHASE_A_MAX_TURNS = 200


def _phase_b_task_key(cfg_id: str) -> str:
    return f"stage2:build:{cfg_id}"


@dataclass
class DeploymentConfig:
    id: str
    name: str
    deployment_mode_path: str
    exposed_surface: list[str]
    modules_exercised: list[str]
    artifact_path: str | None
    launch_cmd: str | None


@dataclass
class Stage2Output:
    manifest_path: str
    deployment_summary_path: str
    configs: list[DeploymentConfig]


_RESULT_FIELDS = (
    "build_status",
    "artifact_path",
    "launch_cmd",
    "build_failure_reason",
    "attempts_summary",
)


def _load_manifest(manifest_path: str) -> dict:
    with open(manifest_path) as f:
        return json.load(f)


def _save_manifest(manifest_path: str, manifest: dict) -> None:
    with open(manifest_path, "w") as f:
        json.dump(manifest, f, indent=2)


def merge_results_into_manifest(deployments_dir: str) -> None:
    """Fold per-config result.json outcomes into manifest.json.

    Missing or malformed result.json entries are downgraded to
    build_status='infeasible' with a build_failure_reason describing the
    validation problem so downstream stages see consistent semantics.
    """
    manifest_path = os.path.join(deployments_dir, "manifest.json")
    manifest = _load_manifest(manifest_path)

    for entry in manifest.get("configs", []):
        cfg_id = entry.get("id")
        if not cfg_id:
            continue
        cfg_dir = os.path.join(deployments_dir, "configs", cfg_id)
        result_path = os.path.join(cfg_dir, "result.json")

        if not os.path.exists(result_path):
            entry["build_status"] = "infeasible"
            entry["build_failure_reason"] = "result.json missing — Phase B did not produce an outcome."
            entry["attempts_summary"] = entry.get("attempts_summary") or "n/a"
            entry.setdefault("artifact_path", None)
            entry.setdefault("launch_cmd", None)
            continue

        issues: list[ValidationIssue] = validate_stage2_phase_b_entry(cfg_dir)
        if issues:
            logger.warning(
                "Stage 2 merge: result.json for %s failed validation, downgrading to infeasible:\n%s",
                cfg_id, format_validation_issues(issues),
            )
            entry["build_status"] = "infeasible"
            entry["build_failure_reason"] = (
                f"result.json failed validation: {format_validation_issues(issues)}"
            )
            entry["attempts_summary"] = entry.get("attempts_summary") or "n/a"
            entry["artifact_path"] = None
            entry["launch_cmd"] = None
            continue

        with open(result_path) as f:
            data = json.load(f)
        for field in _RESULT_FIELDS:
            entry[field] = data.get(field)

    _save_manifest(manifest_path, manifest)


def load_stage2_output(deployments_dir: str) -> Stage2Output:
    """Read a merged manifest and return only the entries with build_status == 'ok'."""
    manifest_path = os.path.join(deployments_dir, "manifest.json")
    summary_path = os.path.join(deployments_dir, "deployment-summary.md")
    manifest = _load_manifest(manifest_path)

    configs: list[DeploymentConfig] = []
    for entry in manifest.get("configs", []):
        if entry.get("build_status") != "ok":
            continue
        configs.append(DeploymentConfig(
            id=entry["id"],
            name=entry.get("name", ""),
            deployment_mode_path=os.path.join(deployments_dir, entry.get("deployment_mode_path", "")),
            exposed_surface=list(entry.get("exposed_surface", [])),
            modules_exercised=list(entry.get("modules_exercised", [])),
            artifact_path=entry.get("artifact_path"),
            launch_cmd=entry.get("launch_cmd"),
        ))
    return Stage2Output(
        manifest_path=manifest_path,
        deployment_summary_path=summary_path,
        configs=configs,
    )


async def _run_phase_a(
    config: AuditConfig,
    checkpoint: CheckpointManager,
    deployments_dir: str,
    auditing_focus_path: str,
) -> None:
    """Run the deployment research agent and validate its output."""
    if checkpoint.is_complete(_PHASE_A_TASK_KEY):
        logger.info("Stage 2 Phase A: already complete, skipping.")
        return

    os.makedirs(os.path.join(deployments_dir, "configs"), exist_ok=True)
    log_file = os.path.join(deployments_dir, "agent.log")

    research_record_path = os.path.join(
        config.output_dir, "stage1-security-context", "stage-1-security-context.json",
    )
    auditing_focus_str = auditing_focus_path

    prompt = load_prompt("stage2.md", {
        "target_path": config.target,
        "deployments_dir": deployments_dir,
        "configs_dir": os.path.join(deployments_dir, "configs"),
        "manifest_path": os.path.join(deployments_dir, "manifest.json"),
        "summary_path": os.path.join(deployments_dir, "deployment-summary.md"),
        "auditing_focus_path": auditing_focus_str,
        "research_record_path": research_record_path,
    })

    logger.info("Stage 2 Phase A: starting deployment research.")
    await run_agent(
        prompt,
        config,
        cwd=config.target,
        max_turns=_PHASE_A_MAX_TURNS,
        log_file=log_file,
    )

    issues = validate_stage2_phase_a(deployments_dir)
    if issues:
        logger.warning(
            "Stage 2 Phase A: validation issues:\n%s",
            format_validation_issues(issues),
        )
        repair_prompt = (
            f"The deployment manifest at `{deployments_dir}` failed validation. "
            "Please fix all issues listed below:\n\n"
            f"```\n{format_validation_issues(issues)}\n```"
        )
        await run_agent(
            repair_prompt, config, cwd=config.target,
            max_turns=10, log_file=log_file,
        )
        issues = validate_stage2_phase_a(deployments_dir)
        if issues:
            logger.warning(
                "Stage 2 Phase A: validation still failing after repair:\n%s",
                format_validation_issues(issues),
            )

    checkpoint.mark_complete(_PHASE_A_TASK_KEY)
    logger.info("Stage 2 Phase A: complete.")
