from __future__ import annotations

import os

from ..config import ValidationIssue
from ..poc_artifacts import TRIGGER_GRAPH_FILENAME, load_trigger_graph


def validate_stage5_trigger_graph(
    poc_dir: str,
    finding_id: str,
) -> list[ValidationIssue]:
    """Validate the interactive PoC trigger graph produced by Stage 5."""
    graph_path = os.path.join(poc_dir, TRIGGER_GRAPH_FILENAME)
    _, errors = load_trigger_graph(
        graph_path,
        expected_finding_id=finding_id,
    )
    return [
        ValidationIssue(
            description=error,
            expected=(
                f"{TRIGGER_GRAPH_FILENAME} must describe a bounded, evidence-backed "
                "call path from attacker-controlled source to vulnerability sink."
            ),
            fix=f"Correct {graph_path} without inventing runtime evidence.",
        )
        for error in errors
    ]
