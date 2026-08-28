from __future__ import annotations

import asyncio
import os
import subprocess

from ..config import AuditConfig
from ..logger import get_logger
from ..process_tree import current_audit_subprocess_env

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
        env=current_audit_subprocess_env(),
    )
    has_changes = bool(status.stdout.strip())

    if has_changes:
        logger.info("Stashing uncommitted changes before pull.")
        subprocess.run(
            ["git", "stash", "--include-untracked"],
            cwd=target, capture_output=True, text=True, check=True,
            env=current_audit_subprocess_env(),
        )

    try:
        result = subprocess.run(
            ["git", "pull"],
            cwd=target, capture_output=True, text=True, check=True,
            env=current_audit_subprocess_env(),
        )
        logger.info("git pull: %s", result.stdout.strip() or "up to date")
    finally:
        if has_changes:
            logger.info("Restoring stashed changes.")
            try:
                subprocess.run(
                    ["git", "stash", "pop"],
                    cwd=target, capture_output=True, text=True, check=True,
                    env=current_audit_subprocess_env(),
                )
            except subprocess.CalledProcessError as e:
                logger.warning(
                    "Failed to restore stashed changes (merge conflict?): %s\n"
                    "stderr: %s\n"
                    "Your changes remain in the stash. Run 'git stash pop' manually to recover them.",
                    e, e.stderr.strip() if e.stderr else "",
                )


async def run_setup(config: AuditConfig) -> None:
    if _is_git_repo(config.target) and config.update_repo:
        # ``git status`` and especially ``git pull`` can take seconds.  Stage 0
        # is launched immediately after the Web start endpoint creates its
        # background task, so running them on the event-loop thread delays the
        # HTTP 202 response (and every other Web request).  Keep the blocking
        # subprocess sequence intact, but move it to a worker thread.
        await asyncio.to_thread(_git_pull, config.target)
    elif _is_git_repo(config.target):
        logger.info(
            "Git update disabled; auditing the existing checkout at %s.",
            config.target,
        )

    directories = [
        config.output_dir,
        os.path.join(config.output_dir, ".markers"),
        os.path.join(config.output_dir, "stage1-security-context"),
        os.path.join(config.output_dir, "stage2-analysis-units"),
        os.path.join(config.output_dir, "stage3-findings"),
        os.path.join(config.output_dir, "stage4-vulnerabilities"),
        os.path.join(config.output_dir, "stage4-vulnerabilities", "_pending"),
        os.path.join(config.output_dir, "stage5-pocs"),
        os.path.join(config.output_dir, "stage6-disclosures"),
    ]

    for directory in directories:
        os.makedirs(directory, exist_ok=True)
        logger.debug("Directory ready: %s", directory)

    logger.info("Stage 0 complete. Output dir: %s", config.output_dir)
