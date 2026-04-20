from __future__ import annotations

import os
import subprocess

from ..config import AuditConfig
from ..logger import get_logger

logger = get_logger("stage0")


def _is_git_repo(path: str) -> bool:
    return os.path.isdir(os.path.join(path, ".git"))


def _git_pull(target: str) -> None:
    """Stash uncommitted changes if any, pull latest, then restore the stash."""
    logger.info("Target is a git repo. Pulling latest changes...")

    # Check for uncommitted changes (staged, unstaged, or untracked)
    status = subprocess.run(
        ["git", "status", "--porcelain"],
        cwd=target, capture_output=True, text=True, check=True,
    )
    has_changes = bool(status.stdout.strip())

    if has_changes:
        logger.info("Stashing uncommitted changes before pull.")
        subprocess.run(
            ["git", "stash", "--include-untracked"],
            cwd=target, capture_output=True, text=True, check=True,
        )

    try:
        result = subprocess.run(
            ["git", "pull"],
            cwd=target, capture_output=True, text=True, check=True,
        )
        logger.info("git pull: %s", result.stdout.strip() or "up to date")
    finally:
        if has_changes:
            logger.info("Restoring stashed changes.")
            subprocess.run(
                ["git", "stash", "pop"],
                cwd=target, capture_output=True, text=True, check=True,
            )


async def run_setup(config: AuditConfig) -> None:
    if _is_git_repo(config.target):
        _git_pull(config.target)

    directories = [
        config.output_dir,
        os.path.join(config.output_dir, ".markers"),
        os.path.join(config.output_dir, "stage1-security-context"),
        os.path.join(config.output_dir, "stage2-deployments"),
        os.path.join(config.output_dir, "stage2-deployments", "configs"),
        os.path.join(config.output_dir, "stage3-analysis-units"),
        os.path.join(config.output_dir, "stage4-findings"),
        os.path.join(config.output_dir, "stage5-vulnerabilities"),
        os.path.join(config.output_dir, "stage5-vulnerabilities", "_pending"),
        os.path.join(config.output_dir, "stage6-pocs"),
        os.path.join(config.output_dir, "stage7-disclosures"),
    ]

    for directory in directories:
        os.makedirs(directory, exist_ok=True)
        logger.debug("Directory ready: %s", directory)

    logger.info("Stage 0 complete. Output dir: %s", config.output_dir)
