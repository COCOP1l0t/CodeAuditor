from __future__ import annotations

import json
import os
import re
import shutil

from ..agent import run_agent
from ..checkpoint import CheckpointManager
from ..config import AnalysisUnit, AuditConfig, Module
from ..logger import get_logger
from ..prompts import load_prompt
from ..utils import format_validation_issues, list_matching_files, run_parallel_limited
from ..validation.stage2 import validate_stage2_file

logger = get_logger("stage2")


def _task_key(module: Module) -> str:
    return f"stage2:{module.id}"


async def _run_module_agent(
    module: Module,
    config: AuditConfig,
    checkpoint: CheckpointManager,
    stage1_output: str,
) -> None:
    key = _task_key(module)
    draft_dir = os.path.join(config.output_dir, "stage-2-details")

    if checkpoint.is_complete(key):
        logger.info("Stage 2: %s agent already complete.", module.id)
        return

    logger.info("Stage 2: Starting analysis of module %s.", module.id)
    prompt = load_prompt("stage2.md", {
        "stage1_output_path": stage1_output,
        "result_dir": draft_dir,
        "module_id": module.id,
    })

    await run_agent(prompt, config, cwd=config.target)

    # Validate each AU file the agent wrote for this module.
    pattern = re.compile(rf"^{re.escape(module.id)}-\d+\.json$")
    au_files = list_matching_files(draft_dir, pattern)
    for au_file in au_files:
        issues = validate_stage2_file(au_file)
        if not issues:
            continue
        logger.warning("Stage 2: Validation failed for %s\n%s", au_file, format_validation_issues(issues))
        repair_prompt = (
            f"The analysis unit file at `{au_file}` failed validation. "
            f"Please fix all issues listed below:\n\n```\n{format_validation_issues(issues)}\n```"
        )
        await run_agent(repair_prompt, config, cwd=config.target, max_turns=10)

    checkpoint.mark_complete(key)
    logger.info("Stage 2: %s agent done.", module.id)


def _collect_already_renumbered(draft_dir: str) -> list[AnalysisUnit]:
    """On resume, collect AU-{N}.json files that were already renumbered in a previous run."""
    pattern = re.compile(r"^AU-(\d+)\.json$")
    au_files = list_matching_files(draft_dir, pattern)
    units: list[AnalysisUnit] = []
    for path in au_files:
        try:
            with open(path) as f:
                data = json.load(f)
        except (json.JSONDecodeError, OSError) as e:
            logger.warning("Stage 2: Failed to read existing AU file %s: %s, skipping.", path, e)
            continue
        au_id = data.get("id", os.path.basename(path).removesuffix(".json"))
        module_id = data.get("module_id", "unknown")
        units.append(AnalysisUnit(id=au_id, module_id=module_id, au_file_path=path))
    # Sort by numeric AU id so ordering is deterministic.
    units.sort(key=lambda u: int(u.id.removeprefix("AU-")) if u.id.startswith("AU-") else 0)
    return units


def _collect_and_renumber(
    modules: list[Module],
    draft_dir: str,
    config: AuditConfig,
) -> list[AnalysisUnit]:
    """Collect per-module AU files and renumber them to global AU-{N} IDs.

    If module draft files (M-{N}-*.json) have already been renumbered to AU-{N}.json
    (e.g. from a previous run), load those directly instead.
    """
    # Check if any module-prefixed drafts still exist.
    has_drafts = False
    for module in modules:
        pattern = re.compile(rf"^{re.escape(module.id)}-\d+\.json$")
        if list_matching_files(draft_dir, pattern):
            has_drafts = True
            break

    # If no drafts remain, the renumbering already happened — load existing AU files.
    if not has_drafts:
        existing = _collect_already_renumbered(draft_dir)
        if existing:
            return existing

    all_units: list[AnalysisUnit] = []
    next_au_number = 1

    for module in modules:
        pattern = re.compile(rf"^{re.escape(module.id)}-\d+\.json$")
        au_files = list_matching_files(draft_dir, pattern)
        if not au_files:
            logger.warning("Stage 2: No AU files found for %s.", module.id)
            continue

        for src_path in au_files:
            au_id = f"AU-{next_au_number}"
            next_au_number += 1
            dest_path = os.path.join(draft_dir, f"{au_id}.json")

            # Read the agent's output and add orchestrator fields.
            try:
                with open(src_path) as f:
                    data = json.load(f)
            except (json.JSONDecodeError, OSError) as e:
                logger.warning("Stage 2: Failed to read %s: %s, skipping.", src_path, e)
                continue

            data["id"] = au_id
            data["module_id"] = module.id
            data["project_root"] = config.target

            with open(dest_path, "w") as f:
                json.dump(data, f, indent=2)

            # Remove the original module-prefixed file.
            if os.path.realpath(src_path) != os.path.realpath(dest_path):
                os.remove(src_path)

            logger.info("Stage 2: %s -> %s (from %s)", os.path.basename(src_path), au_id, module.id)
            all_units.append(AnalysisUnit(id=au_id, module_id=module.id, au_file_path=dest_path))

    return all_units


async def run_stage2(
    modules: list[Module],
    config: AuditConfig,
    checkpoint: CheckpointManager,
) -> list[AnalysisUnit]:
    stage1_output = os.path.join(config.output_dir, "stage-1-modules.json")
    draft_dir = os.path.join(config.output_dir, "stage-2-details")

    results = await run_parallel_limited(
        modules,
        config.max_parallel,
        lambda module, _: _run_module_agent(module, config, checkpoint, stage1_output),
    )

    for i, (status, _, error) in enumerate(results):
        if status == "rejected" and i < len(modules):
            logger.error("Stage 2: %s agent failed: %s", modules[i].id, error)

    units = _collect_and_renumber(modules, draft_dir, config)
    logger.info("Stage 2 complete. Analysis units: %s", ", ".join(u.id for u in units))
    return units
