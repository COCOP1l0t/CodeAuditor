from __future__ import annotations

import asyncio
import os
import subprocess

from ..config import AuditConfig
from ..layout import markers_dir, stage4_paths, stage_dir
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
        markers_dir(config.output_dir),
        stage_dir(config.output_dir, 1),
        stage_dir(config.output_dir, 2),
        stage_dir(config.output_dir, 3),
        stage_dir(config.output_dir, 4),
        stage4_paths(config.output_dir)["pending"],
        stage_dir(config.output_dir, 5),
        stage_dir(config.output_dir, 6),
    ]

    for directory in directories:
        os.makedirs(directory, exist_ok=True)
        logger.debug("Directory ready: %s", directory)

    logger.info("Stage 0 complete. Output dir: %s", config.output_dir)
