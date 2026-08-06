"""Standard Stage 5 evidence artifact names and trigger-graph validation."""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

TRIGGER_GRAPH_FILENAME = "trigger-graph.json"
ASAN_REPORT_FILENAME = "asan-report.txt"
TRIGGER_GRAPH_SCHEMA_VERSION = 1
MAX_TRIGGER_GRAPH_BYTES = 2 * 1024 * 1024
MAX_TRIGGER_GRAPH_NODES = 128
MAX_TRIGGER_GRAPH_EDGES = 256

TRIGGER_GRAPH_NODE_ROLES = {
    "trigger",
    "source",
    "propagation",
    "guard",
    "sink",
    "source-and-sink",
}

_NODE_ID_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_.:-]{0,63}$")


def _required_text(
    value: Any,
    field: str,
    errors: list[str],
    *,
    max_length: int,
) -> str:
    if not isinstance(value, str) or not value.strip():
        errors.append(f"{field} must be a non-empty string")
        return ""
    text = value.strip()
    if len(text) > max_length:
        errors.append(f"{field} must not exceed {max_length} characters")
    return text


def _optional_text(
    value: Any,
    field: str,
    errors: list[str],
    *,
    max_length: int,
) -> None:
    if value is None:
        return
    if not isinstance(value, str):
        errors.append(f"{field} must be a string when present")
    elif len(value) > max_length:
        errors.append(f"{field} must not exceed {max_length} characters")


def validate_trigger_graph_data(
    data: Any,
    *,
    expected_finding_id: str | None = None,
) -> list[str]:
    """Validate the bounded JSON schema used by the interactive Web graph."""
    errors: list[str] = []
    if not isinstance(data, dict):
        return ["trigger graph must be a JSON object"]

    if data.get("schema_version") != TRIGGER_GRAPH_SCHEMA_VERSION:
        errors.append(
            f"schema_version must be {TRIGGER_GRAPH_SCHEMA_VERSION}"
        )
    finding_id = _required_text(
        data.get("finding_id"), "finding_id", errors, max_length=64
    )
    if expected_finding_id and finding_id and finding_id != expected_finding_id:
        errors.append(
            f"finding_id must match the Stage 5 vulnerability ID {expected_finding_id}"
        )
    _required_text(data.get("title"), "title", errors, max_length=512)
    _required_text(data.get("trigger"), "trigger", errors, max_length=4096)
    _required_text(
        data.get("evidence_basis"),
        "evidence_basis",
        errors,
        max_length=4096,
    )

    nodes = data.get("nodes")
    if not isinstance(nodes, list) or not nodes:
        errors.append("nodes must be a non-empty array")
        nodes = []
    elif len(nodes) > MAX_TRIGGER_GRAPH_NODES:
        errors.append(
            f"nodes must contain at most {MAX_TRIGGER_GRAPH_NODES} entries"
        )

    node_ids: set[str] = set()
    source_ids: set[str] = set()
    sink_ids: set[str] = set()
    for index, node in enumerate(nodes):
        prefix = f"nodes[{index}]"
        if not isinstance(node, dict):
            errors.append(f"{prefix} must be an object")
            continue
        node_id = _required_text(
            node.get("id"), f"{prefix}.id", errors, max_length=64
        )
        if node_id and _NODE_ID_RE.fullmatch(node_id) is None:
            errors.append(f"{prefix}.id contains unsupported characters")
        if node_id in node_ids:
            errors.append(f"{prefix}.id must be unique")
        elif node_id:
            node_ids.add(node_id)
        _required_text(
            node.get("function"), f"{prefix}.function", errors, max_length=512
        )
        _required_text(
            node.get("location"), f"{prefix}.location", errors, max_length=1024
        )
        role = node.get("role")
        if role not in TRIGGER_GRAPH_NODE_ROLES:
            errors.append(
                f"{prefix}.role must be one of: "
                + ", ".join(sorted(TRIGGER_GRAPH_NODE_ROLES))
            )
        if node_id and role in {"trigger", "source", "source-and-sink"}:
            source_ids.add(node_id)
        if node_id and role in {"sink", "source-and-sink"}:
            sink_ids.add(node_id)
        _required_text(
            node.get("description"),
            f"{prefix}.description",
            errors,
            max_length=4096,
        )
        _optional_text(
            node.get("evidence"),
            f"{prefix}.evidence",
            errors,
            max_length=4096,
        )

        parameters = node.get("key_parameters", [])
        if not isinstance(parameters, list):
            errors.append(f"{prefix}.key_parameters must be an array")
            continue
        if len(parameters) > 32:
            errors.append(f"{prefix}.key_parameters must contain at most 32 entries")
        for parameter_index, parameter in enumerate(parameters):
            parameter_prefix = f"{prefix}.key_parameters[{parameter_index}]"
            if not isinstance(parameter, dict):
                errors.append(f"{parameter_prefix} must be an object")
                continue
            _required_text(
                parameter.get("name"),
                f"{parameter_prefix}.name",
                errors,
                max_length=256,
            )
            for field in ("value", "origin", "security_role", "description"):
                _optional_text(
                    parameter.get(field),
                    f"{parameter_prefix}.{field}",
                    errors,
                    max_length=2048,
                )

    edges = data.get("edges")
    if not isinstance(edges, list):
        errors.append("edges must be an array")
        edges = []
    elif len(edges) > MAX_TRIGGER_GRAPH_EDGES:
        errors.append(
            f"edges must contain at most {MAX_TRIGGER_GRAPH_EDGES} entries"
        )

    adjacency: dict[str, set[str]] = {node_id: set() for node_id in node_ids}
    for index, edge in enumerate(edges):
        prefix = f"edges[{index}]"
        if not isinstance(edge, dict):
            errors.append(f"{prefix} must be an object")
            continue
        source = _required_text(
            edge.get("from"), f"{prefix}.from", errors, max_length=64
        )
        target = _required_text(
            edge.get("to"), f"{prefix}.to", errors, max_length=64
        )
        if source and source not in node_ids:
            errors.append(f"{prefix}.from must reference an existing node")
        if target and target not in node_ids:
            errors.append(f"{prefix}.to must reference an existing node")
        if source in adjacency and target in node_ids:
            adjacency[source].add(target)
        _required_text(
            edge.get("label"), f"{prefix}.label", errors, max_length=512
        )
        _optional_text(
            edge.get("condition"),
            f"{prefix}.condition",
            errors,
            max_length=2048,
        )
        if "attacker_controlled" in edge and not isinstance(
            edge["attacker_controlled"], bool
        ):
            errors.append(f"{prefix}.attacker_controlled must be a boolean")

    if nodes and not source_ids:
        errors.append("at least one trigger/source node is required")
    if nodes and not sink_ids:
        errors.append("at least one sink node is required")
    if source_ids and sink_ids:
        reachable = set(source_ids)
        pending = list(source_ids)
        while pending:
            current = pending.pop()
            for target in adjacency.get(current, set()):
                if target not in reachable:
                    reachable.add(target)
                    pending.append(target)
        if not reachable.intersection(sink_ids):
            errors.append("the graph must contain a path from a trigger/source to a sink")
    return errors


def load_trigger_graph(
    path: str,
    *,
    expected_finding_id: str | None = None,
) -> tuple[dict[str, Any] | None, list[str]]:
    """Read and validate one bounded Stage 5 trigger graph file."""
    graph_path = Path(path)
    try:
        if graph_path.stat().st_size > MAX_TRIGGER_GRAPH_BYTES:
            return None, [
                f"trigger graph exceeds {MAX_TRIGGER_GRAPH_BYTES} bytes"
            ]
        data = json.loads(graph_path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None, [f"missing {TRIGGER_GRAPH_FILENAME}"]
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        return None, [f"cannot read {TRIGGER_GRAPH_FILENAME}: {exc}"]
    errors = validate_trigger_graph_data(
        data, expected_finding_id=expected_finding_id
    )
    return (data if not errors and isinstance(data, dict) else None), errors
