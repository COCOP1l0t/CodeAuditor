from __future__ import annotations

import json
import os
from dataclasses import dataclass
from datetime import datetime, timedelta

from ..agent import run_with_validation
from ..checkpoint import CheckpointManager
from ..config import AuditConfig
from ..logger import get_logger
from ..prompts import load_prompt
from ..validation.stage1 import validate_stage1_file
from ..wiki import build_wiki_context

logger = get_logger("stage1")
_TASK_KEY = "stage1"


@dataclass
class Stage1Output:
    research_record_path: str
    auditing_focus_path: str
    vuln_criteria_path: str


async def run_stage1(
    config: AuditConfig,
    checkpoint: CheckpointManager,
) -> Stage1Output:
    details_dir = os.path.join(config.output_dir, "stage1-security-context")
    research_record_path = os.path.join(details_dir, "stage-1-security-context.json")
    auditing_focus_path = os.path.join(details_dir, "auditing-focus.md")
    vuln_criteria_path = os.path.join(details_dir, "vulnerability-criteria.md")

    if checkpoint.is_complete(_TASK_KEY):
        logger.info("Stage 1 already complete, loading existing output.")
        return Stage1Output(
            research_record_path=research_record_path,
            auditing_focus_path=auditing_focus_path,
            vuln_criteria_path=vuln_criteria_path,
        )

    today = datetime.now().strftime("%Y-%m-%d")
    start_date = (datetime.now() - timedelta(days=int(5 * 365.25))).strftime("%Y-%m-%d")

    prompt = load_prompt("stage1.md", {
        "target_path": config.target,
        "output_path": research_record_path,
        "auditing_focus_path": auditing_focus_path,
        "vuln_criteria_path": vuln_criteria_path,
        "today": today,
        "start_date": start_date,
        "user_instructions": config.scope or "No additional scope constraints.",
        "wiki_context": build_wiki_context(config, stage=1),
    })

    passed, _ = await run_with_validation(
        prompt=prompt,
        config=config,
        cwd=config.target,
        output_path=research_record_path,
        validator=validate_stage1_file,
        max_turns=200,
        log_file=os.path.join(details_dir, "agent.log"),
    )

    if not passed:
        logger.warning("Stage 1 validation did not fully pass, continuing with best-effort output.")

    checkpoint.mark_complete(_TASK_KEY)
    logger.info("Stage 1 complete. Research record: %s", research_record_path)
    return Stage1Output(
        research_record_path=research_record_path,
        auditing_focus_path=auditing_focus_path,
        vuln_criteria_path=vuln_criteria_path,
    )
