from __future__ import annotations

import json
import os
import re
from typing import Any

from ..config import ValidationIssue

_KEBAB_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
_VACUOUS_REASONS = {"build failed", "unknown error", "failed", "error"}
_VALID_BUILD_STATUSES = {"ok", "infeasible", "timeout"}
_PHASE_A_BUILD_FIELDS = (
    "build_status",
    "artifact_path",
    "launch_cmd",
    "build_failure_reason",
    "attempts_summary",
)


def _issue(description: str, expected: str, fix: str) -> ValidationIssue:
    return ValidationIssue(description=description, expected=expected, fix=fix)


def _is_nonempty_string(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _is_nonempty_list_of_strings(value: Any) -> bool:
    return (
        isinstance(value, list)
        and len(value) > 0
        and all(isinstance(x, str) and x.strip() for x in value)
    )


def _read_json(path: str) -> tuple[Any, list[ValidationIssue]]:
    if not os.path.exists(path):
        return None, [_issue(
            description=f"File not found: {path}",
            expected="The file should exist.",
            fix="Ensure the file is written before validation.",
        )]
    try:
        with open(path) as f:
            return json.load(f), []
    except json.JSONDecodeError as e:
        return None, [_issue(
            description=f"{os.path.basename(path)}: invalid JSON: {e}",
            expected="Valid JSON.",
            fix="Fix the JSON syntax error.",
        )]


def validate_stage2_phase_a(deployments_dir: str) -> list[ValidationIssue]:
    """Validate the layout produced by Phase A (research) before Phase B runs."""
    issues: list[ValidationIssue] = []

    if not os.path.isdir(deployments_dir):
        return [_issue(
            description=f"Deployments directory does not exist: {deployments_dir}",
            expected="A directory containing manifest.json, deployment-summary.md, and configs/.",
            fix="Run the Phase A research agent.",
        )]

    summary_path = os.path.join(deployments_dir, "deployment-summary.md")
    if not os.path.exists(summary_path) or os.path.getsize(summary_path) == 0:
        issues.append(_issue(
            description="deployment-summary.md is missing or empty.",
            expected="A non-empty summary file at deployment-summary.md.",
            fix="Write deployment-summary.md with one paragraph per archetype.",
        ))

    manifest_path = os.path.join(deployments_dir, "manifest.json")
    data, read_issues = _read_json(manifest_path)
    issues.extend(read_issues)
    if data is None:
        return issues

    if not isinstance(data, dict) or "configs" not in data:
        issues.append(_issue(
            description="manifest.json: missing top-level 'configs' array.",
            expected="A JSON object with a 'configs' array.",
            fix="Wrap the entries in {\"configs\": [...]}.",
        ))
        return issues

    configs = data["configs"]
    if not isinstance(configs, list):
        issues.append(_issue(
            description="manifest.json: 'configs' is not a list.",
            expected="A JSON array.",
            fix="Make 'configs' a JSON array.",
        ))
        return issues

    if len(configs) == 0:
        issues.append(_issue(
            description="manifest.json: 'configs' must contain at least one archetype.",
            expected="At least one deployment archetype.",
            fix="Add at least one archetype to 'configs'.",
        ))
        return issues

    seen_ids: set[str] = set()
    for i, entry in enumerate(configs):
        if not isinstance(entry, dict):
            issues.append(_issue(
                description=f"manifest.json[{i}]: entry is not an object.",
                expected="Each entry must be a JSON object.",
                fix=f"Fix entry at index {i}.",
            ))
            continue

        cfg_id = entry.get("id")
        if not _is_nonempty_string(cfg_id):
            issues.append(_issue(
                description=f"manifest.json[{i}]: missing or blank 'id'.",
                expected="A non-empty kebab-case id.",
                fix=f"Add an 'id' to entry {i}.",
            ))
            continue

        if not _KEBAB_RE.match(cfg_id):
            issues.append(_issue(
                description=f"manifest.json[{i}]: id '{cfg_id}' is not kebab-case.",
                expected="kebab-case (lowercase letters, digits, hyphens).",
                fix=f"Rename '{cfg_id}' to kebab-case.",
            ))

        if cfg_id in seen_ids:
            issues.append(_issue(
                description=f"manifest.json[{i}]: duplicate id '{cfg_id}'.",
                expected="Unique ids across the manifest.",
                fix=f"Pick a different id for one of the duplicates.",
            ))
        seen_ids.add(cfg_id)

        if not _is_nonempty_string(entry.get("name")):
            issues.append(_issue(
                description=f"manifest.json[{cfg_id}]: missing or blank 'name'.",
                expected="A short human-readable name.",
                fix="Add a 'name'.",
            ))

        if not _is_nonempty_list_of_strings(entry.get("exposed_surface")):
            issues.append(_issue(
                description=f"manifest.json[{cfg_id}]: 'exposed_surface' must be a non-empty list of strings.",
                expected="Non-empty list of strings.",
                fix="Add at least one exposed-surface entry.",
            ))

        if not _is_nonempty_list_of_strings(entry.get("modules_exercised")):
            issues.append(_issue(
                description=f"manifest.json[{cfg_id}]: 'modules_exercised' must be a non-empty list of strings.",
                expected="Non-empty list of strings.",
                fix="Add at least one module path.",
            ))

        dm_path_rel = entry.get("deployment_mode_path")
        if not _is_nonempty_string(dm_path_rel):
            issues.append(_issue(
                description=f"manifest.json[{cfg_id}]: missing or blank 'deployment_mode_path'.",
                expected="A path relative to the deployments dir.",
                fix=f"Set 'deployment_mode_path' to configs/{cfg_id}/deployment-mode.md",
            ))
        else:
            dm_path = os.path.join(deployments_dir, dm_path_rel)
            if not os.path.exists(dm_path):
                issues.append(_issue(
                    description=f"{cfg_id}: deployment-mode.md does not exist at {dm_path_rel}.",
                    expected="A non-empty deployment-mode.md file.",
                    fix=f"Write deployment-mode.md for {cfg_id}.",
                ))
            elif os.path.getsize(dm_path) == 0:
                issues.append(_issue(
                    description=f"{cfg_id}: deployment-mode.md is empty at {dm_path_rel}.",
                    expected="A non-empty file describing the deployment mode.",
                    fix=f"Write a deployment-mode body for {cfg_id}.",
                ))

        for build_field in _PHASE_A_BUILD_FIELDS:
            if entry.get(build_field) is not None:
                issues.append(_issue(
                    description=f"manifest.json[{cfg_id}]: '{build_field}' must be null after Phase A.",
                    expected=f"'{build_field}' is null until Phase B runs.",
                    fix=f"Remove the '{build_field}' value or set it to null.",
                ))

    return issues


def validate_stage2_phase_b_entry(config_dir: str) -> list[ValidationIssue]:
    """Validate the per-config result.json + script artifacts produced by a Phase B agent."""
    issues: list[ValidationIssue] = []

    expected_id = os.path.basename(os.path.normpath(config_dir))
    result_path = os.path.join(config_dir, "result.json")

    data, read_issues = _read_json(result_path)
    issues.extend(read_issues)
    if data is None:
        return issues

    if not isinstance(data, dict):
        return issues + [_issue(
            description=f"{expected_id}/result.json: top-level value is not an object.",
            expected="A JSON object.",
            fix="Wrap the contents in {...}.",
        )]

    actual_id = data.get("id")
    if actual_id != expected_id:
        issues.append(_issue(
            description=f"{expected_id}/result.json: 'id' ({actual_id!r}) does not match config dir name.",
            expected=f"id == {expected_id!r}",
            fix=f"Set 'id' to '{expected_id}' in result.json.",
        ))

    status = data.get("build_status")
    if status not in _VALID_BUILD_STATUSES:
        issues.append(_issue(
            description=f"{expected_id}/result.json: 'build_status' must be one of {sorted(_VALID_BUILD_STATUSES)}, got {status!r}.",
            expected=f"build_status ∈ {sorted(_VALID_BUILD_STATUSES)}",
            fix="Set build_status to one of the allowed values.",
        ))
        return issues  # downstream checks depend on a valid status

    if status == "ok":
        artifact_path = data.get("artifact_path")
        launch_cmd = data.get("launch_cmd")
        if not _is_nonempty_string(artifact_path):
            issues.append(_issue(
                description=f"{expected_id}/result.json: 'artifact_path' must be a non-empty string when build_status == 'ok'.",
                expected="A path to the launchable artifact.",
                fix="Set artifact_path to the built artifact path.",
            ))
        elif not os.path.exists(artifact_path):
            issues.append(_issue(
                description=f"{expected_id}/result.json: 'artifact_path' does not exist on disk: {artifact_path}.",
                expected="An existing artifact path.",
                fix="Verify the build produced the artifact at this path.",
            ))
        if not _is_nonempty_string(launch_cmd):
            issues.append(_issue(
                description=f"{expected_id}/result.json: 'launch_cmd' must be a non-empty string when build_status == 'ok'.",
                expected="A shell command (or path to launch.sh).",
                fix="Set launch_cmd.",
            ))

        for script in ("build.sh", "launch.sh", "smoke-test.sh"):
            script_path = os.path.join(config_dir, script)
            if not os.path.exists(script_path):
                issues.append(_issue(
                    description=f"{expected_id}: required script {script} is missing.",
                    expected=f"{script} exists in the config directory.",
                    fix=f"Author {script} as part of the build agent's work.",
                ))
                continue
            if not os.access(script_path, os.X_OK):
                issues.append(_issue(
                    description=f"{expected_id}: {script} is not executable.",
                    expected=f"{script} has the executable bit set.",
                    fix=f"chmod +x {script_path}",
                ))

    else:  # infeasible or timeout
        reason = data.get("build_failure_reason")
        if not _is_nonempty_string(reason):
            issues.append(_issue(
                description=f"{expected_id}/result.json: 'build_failure_reason' is required when build_status == {status!r}.",
                expected="A specific failure reason.",
                fix="Set build_failure_reason to a load-bearing diagnosis.",
            ))
        elif reason.strip().lower() in _VACUOUS_REASONS:
            issues.append(_issue(
                description=f"{expected_id}/result.json: 'build_failure_reason' is vacuous: {reason!r}.",
                expected="A specific, load-bearing reason (not 'build failed', 'unknown error', etc.).",
                fix="Replace with a specific diagnosis (missing dep name, kernel feature, etc.).",
            ))

        if not _is_nonempty_string(data.get("attempts_summary")):
            issues.append(_issue(
                description=f"{expected_id}/result.json: 'attempts_summary' is required when build_status == {status!r}.",
                expected="A short summary of approaches tried.",
                fix="Set attempts_summary.",
            ))

    return issues


def validate_stage2_manifest_final(manifest_path: str) -> list[ValidationIssue]:
    """Validate the merged manifest after Phase B completes.

    Returns warnings (also as ValidationIssue) — the runner should not abort
    on these but should log them.
    """
    data, read_issues = _read_json(manifest_path)
    if read_issues:
        return read_issues

    if not isinstance(data, dict) or not isinstance(data.get("configs"), list):
        return [_issue(
            description="manifest.json: missing 'configs' array.",
            expected="A JSON object with a 'configs' array.",
            fix="Recreate the manifest from per-config result.json files.",
        )]

    configs = data["configs"]
    ok_count = sum(1 for entry in configs if isinstance(entry, dict) and entry.get("build_status") == "ok")
    if ok_count == 0:
        return [_issue(
            description="manifest.json: no entries have build_status == 'ok'.",
            expected="At least one successful build (warning).",
            fix="Investigate per-config result.json files; Stage 6 will fall back to ad-hoc building.",
        )]

    return []
