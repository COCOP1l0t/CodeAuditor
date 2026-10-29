"""Shared, low-cost semantic deduplication for confirmed findings."""

from __future__ import annotations

import asyncio
import json
import os
import re
from dataclasses import dataclass, field
from typing import Any, Callable, Mapping, Sequence

from .agent import run_agent
from .config import AuditConfig
from .disclosures import build_dedupe_key, display_list, single_line
from .logger import get_logger
from .prompts import load_prompt
from .utils import extract_json_object

logger = get_logger("semantic_dedupe")

DEFAULT_MAX_TURNS = 10
DEFAULT_EFFORT = "low"


@dataclass(frozen=True)
class DedupeCandidate:
    candidate_id: str
    title: str
    finding: Mapping[str, Any]
    dedupe_key: str
    payload: Any = None
    extra: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class DedupeDecision:
    candidate_id: str
    decision: str
    matched_dedupe_key: str
    representative_id: str
    reason: str


def candidate_from_finding(
    candidate_id: str,
    finding: Mapping[str, Any],
    *,
    repo_url: str,
    payload: Any = None,
) -> DedupeCandidate:
    title = single_line(finding.get("title")) or candidate_id
    return DedupeCandidate(
        candidate_id=candidate_id,
        title=title,
        finding=finding,
        dedupe_key=build_dedupe_key(dict(finding), repo_url),
        payload=payload,
    )


def _entry_for(candidate: DedupeCandidate) -> dict[str, str]:
    return {
        "dedupe_key": candidate.dedupe_key,
        "title": candidate.title,
        "location": single_line(candidate.finding.get("location")),
        "cwe": ", ".join(
            display_list(
                candidate.finding.get("cwe_id") or candidate.finding.get("cwe")
            )
        ),
        "vulnerability_class": ", ".join(
            display_list(candidate.finding.get("vulnerability_class"))
        ),
        "trigger": single_line(candidate.finding.get("trigger")),
        "summary": single_line(
            candidate.finding.get("summary") or candidate.finding.get("description")
        ),
    }


def _safe_log_name(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "-", value).strip("-") or "candidate"


def _normalize_inventory(
    entries: Sequence[Mapping[str, Any]],
) -> list[dict[str, str]]:
    inventory: list[dict[str, str]] = []
    for raw in entries:
        if not isinstance(raw, Mapping):
            continue
        item = {str(key): single_line(value) for key, value in raw.items()}
        if not item.get("dedupe_key"):
            continue
        inventory.append(item)
    return inventory


async def filter_semantic_duplicates(
    candidates: Sequence[DedupeCandidate],
    known_entries: Sequence[Mapping[str, Any]],
    config: AuditConfig,
    *,
    log_dir: str,
    label: str,
    run_agent_fn: Callable[..., Any] = run_agent,
    load_prompt_fn: Callable[..., str] = load_prompt,
    max_turns: int = DEFAULT_MAX_TURNS,
    effort: str = DEFAULT_EFFORT,
) -> tuple[list[DedupeCandidate], list[DedupeDecision]]:
    """Keep one representative per semantic root cause.

    Existing exact duplicate keys are filtered without an LLM call. Remaining
    candidates are compared against the known inventory and against earlier
    retained candidates in this batch. Prompt/agent failures fail open so a
    transient model issue cannot silently discard a genuine finding.
    """
    project = os.path.basename(os.path.realpath(config.target))
    same_project_entries = [
        entry
        for entry in known_entries
        if isinstance(entry, Mapping)
        and str(entry.get("project") or "") == project
    ]
    # Cross-project entries are useful only as a fallback for installations
    # whose older rows predate project tracking. Otherwise they add noise and
    # can cause unrelated projects to be discussed in dedupe decisions.
    if same_project_entries:
        known_entries = same_project_entries
    inventory = _normalize_inventory(known_entries)
    known_by_key = {
        entry["dedupe_key"]: entry.get("title", entry["dedupe_key"])
        for entry in inventory
    }
    retained: list[DedupeCandidate] = []
    decisions: list[DedupeDecision] = []
    os.makedirs(log_dir, exist_ok=True)

    for candidate in candidates:
        label_text = f"{candidate.candidate_id} ({candidate.title})"
        if candidate.dedupe_key in known_by_key:
            representative = known_by_key[candidate.dedupe_key]
            reason = "exact dedupe key already exists in the Disclosure inventory"
            decisions.append(
                DedupeDecision(
                    candidate_id=candidate.candidate_id,
                    decision="duplicate",
                    matched_dedupe_key=candidate.dedupe_key,
                    representative_id=representative,
                    reason=reason,
                )
            )
            logger.info("%s: filtered %s as exact duplicate: %s", label, label_text, reason)
            continue

        entry = _entry_for(candidate)
        if not inventory:
            retained.append(candidate)
            decisions.append(
                DedupeDecision(
                    candidate_id=candidate.candidate_id,
                    decision="new",
                    matched_dedupe_key="",
                    representative_id=candidate.candidate_id,
                    reason="first candidate in this batch",
                )
            )
            inventory.append(entry)
            known_by_key[candidate.dedupe_key] = candidate.candidate_id
            continue

        phase = "prompt preparation"
        decision = "new"
        matched_key = ""
        reason = ""
        try:
            existing_text = "\n\n".join(
                f"Entry {index + 1}\n"
                + "\n".join(f"- {key}: {known.get(key, '')}" for key in entry)
                for index, known in enumerate(inventory)
            )
            prompt = load_prompt_fn(
                "stage6_semantic_dedupe.md",
                {
                    "candidate_title": candidate.title,
                    "candidate_location": single_line(candidate.finding.get("location")),
                    "candidate_cwe": entry["cwe"],
                    "candidate_vuln_class": entry["vulnerability_class"],
                    "candidate_trigger": entry["trigger"],
                    "candidate_summary": entry["summary"],
                    "existing_entries": existing_text,
                },
            )
            phase = "agent call"
            result = await run_agent_fn(
                prompt,
                config,
                cwd=config.target,
                max_turns=max_turns,
                effort=effort,
                log_file=os.path.join(
                    log_dir, f"{_safe_log_name(candidate.candidate_id)}.log"
                ),
            )
            phase = "response validation"
            json_text = extract_json_object(result)
            if json_text is None:
                raise json.JSONDecodeError("No JSON object found in response", result, 0)
            parsed = json.loads(json_text)
            decision = str(parsed.get("decision", "")).lower()
            matched_key = str(parsed.get("matched_dedupe_key", ""))
            reason = single_line(parsed.get("reason", ""))
            if decision == "duplicate" and matched_key not in known_by_key:
                raise ValueError(
                    "duplicate decision referenced a dedupe key that was not present "
                    "in the supplied inventory"
                )
            if decision == "new" and matched_key:
                raise ValueError("new decision must use an empty matched_dedupe_key")
            if decision not in {"new", "duplicate"}:
                raise ValueError(f"unsupported semantic dedupe decision: {decision!r}")
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logger.warning(
                "%s: semantic dedupe %s failed for %s: %s. Keeping candidate.",
                label,
                phase,
                label_text,
                exc,
            )
            decision = "new"
            matched_key = ""
            reason = f"dedupe failed open during {phase}: {exc}"

        if decision == "duplicate":
            representative_id = known_by_key[matched_key]
            decisions.append(
                DedupeDecision(
                    candidate_id=candidate.candidate_id,
                    decision="duplicate",
                    matched_dedupe_key=matched_key,
                    representative_id=representative_id,
                    reason=reason,
                )
            )
            logger.info(
                "%s: filtered %s as semantic duplicate of %s. Reason: %s",
                label,
                label_text,
                representative_id,
                reason,
            )
            continue

        retained.append(candidate)
        decisions.append(
            DedupeDecision(
                candidate_id=candidate.candidate_id,
                decision="new",
                matched_dedupe_key="",
                representative_id=candidate.candidate_id,
                reason=reason or "distinct root cause",
            )
        )
        inventory.append(entry)
        known_by_key[candidate.dedupe_key] = candidate.candidate_id

    logger.info(
        "%s: semantic dedupe kept %d/%d candidates.",
        label,
        len(retained),
        len(candidates),
    )
    return retained, decisions


def write_dedupe_report(path: str, decisions: Sequence[DedupeDecision]) -> None:
    """Write the deterministic keep/filter audit trail."""
    payload = {
        "schema_version": 1,
        "kept": sum(1 for item in decisions if item.decision == "new"),
        "filtered": sum(1 for item in decisions if item.decision == "duplicate"),
        "decisions": [
            {
                "candidate_id": item.candidate_id,
                "decision": item.decision,
                "matched_dedupe_key": item.matched_dedupe_key,
                "representative_id": item.representative_id,
                "reason": item.reason,
            }
            for item in decisions
        ],
    }
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as stream:
        json.dump(payload, stream, indent=2, ensure_ascii=False)
        stream.write("\n")
    os.replace(tmp, path)
