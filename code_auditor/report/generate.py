from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

from .helpers import list_json_files_sync

_SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}


@dataclass
class GeneratedReportSummary:
    total_findings: int = 0
    severity_counts: dict[str, int] = field(default_factory=dict)


def _parse_research_record(file_path: str) -> tuple[str, str]:
    """Extract project summary and threat context from the stage 1 research record (JSON).

    Returns (project_summary, threat_context).
    """
    try:
        data = json.loads(Path(file_path).read_text())
    except (json.JSONDecodeError, OSError):
        return "", ""

    # Project summary from the "project" object.
    project = data.get("project", {})
    summary_parts: list[str] = []
    if project.get("name"):
        summary_parts.append(f"- **Project**: {project['name']}")
    if project.get("path"):
        summary_parts.append(f"- **Path**: {project['path']}")
    if project.get("language"):
        summary_parts.append(f"- **Language**: {project['language']}")
    if project.get("description"):
        summary_parts.append(f"- **Description**: {project['description']}")
    if project.get("deployment_model"):
        summary_parts.append(f"- **Deployment model**: {project['deployment_model']}")
    project_summary = "\n".join(summary_parts)

    # Threat context from historical vulnerabilities and scope.
    threat_parts: list[str] = []

    scope = data.get("scope_announcements", {})
    in_scope_modules = scope.get("in_scope_modules", [])
    out_of_scope_modules = scope.get("out_of_scope_modules", [])
    in_scope_issue_types = scope.get("in_scope_issue_types", [])
    out_of_scope_issue_types = scope.get("out_of_scope_issue_types", [])
    has_scope = any([in_scope_modules, out_of_scope_modules, in_scope_issue_types, out_of_scope_issue_types])
    if has_scope:
        threat_parts.append("## Scope Announcements\n")
        if in_scope_modules:
            threat_parts.append("**In-scope modules**: " + "; ".join(s for s in in_scope_modules if s))
        if out_of_scope_modules:
            threat_parts.append("**Out-of-scope modules**: " + "; ".join(s for s in out_of_scope_modules if s))
        if in_scope_issue_types:
            threat_parts.append("**In-scope issue types**: " + "; ".join(s for s in in_scope_issue_types if s))
        if out_of_scope_issue_types:
            threat_parts.append("**Out-of-scope issue types**: " + "; ".join(s for s in out_of_scope_issue_types if s))

    vulns = data.get("historical_vulnerabilities", [])
    if vulns:
        threat_parts.append("\n## Known Vulnerabilities and Security History\n")
        for v in vulns:
            parts = []
            if v.get("cve_id"):
                parts.append(f"**{v['cve_id']}**")
            if v.get("date"):
                parts.append(f"({v['date']})")
            if v.get("affected_component"):
                parts.append(f"in {v['affected_component']}")
            if v.get("vulnerability_class"):
                parts.append(f"[{v['vulnerability_class']}]")
            if v.get("severity"):
                parts.append(f"Severity: {v['severity']}")
            summary_text = v.get("summary", "")
            line = " ".join(parts)
            if summary_text:
                line += f" — {summary_text}"
            threat_parts.append(f"- {line}")

    severity_guidance = data.get("severity_guidance", {})
    if severity_guidance.get("notes"):
        threat_parts.append(f"\n## Severity Guidance\n\n{severity_guidance['notes']}")

    return project_summary, "\n".join(threat_parts)


def _parse_finding_file(file_path: str) -> dict | None:
    try:
        with open(file_path) as f:
            return json.load(f)
    except (json.JSONDecodeError, ValueError):
        return None


def _severity_sort_key(finding: dict) -> tuple[int, int]:
    severity = str(finding.get("severity", "Low"))
    severity_rank = _SEVERITY_ORDER.get(severity, 3)
    id_text = str(finding.get("id", "Z-99"))
    number_match = re.search(r"(\d+)$", id_text)
    return (severity_rank, int(number_match.group(1)) if number_match else 99)


def _format_array_field(value: object) -> str:
    if isinstance(value, list):
        return ", ".join(str(item) for item in value)
    return str(value) if value else "\u2013"


def _generate_summary_table(findings: list[dict]) -> str:
    if not findings:
        return "No vulnerabilities found.\n"

    lines = [
        "| ID | Title | Vulnerability Class | Location | CVSS | Severity | CWE |",
        "|----|-------|---------------------|----------|------|----------|-----|",
    ]
    for s in findings:
        lines.append(
            f"| {s.get('id', 'N/A')} "
            f"| {s.get('title', 'N/A')} "
            f"| {_format_array_field(s.get('vulnerability_class'))} "
            f"| {s.get('location', 'N/A')} "
            f"| {s.get('cvss_score', 'N/A')} "
            f"| {s.get('severity', 'N/A')} "
            f"| {_format_array_field(s.get('cwe_id'))} |"
        )
    return "\n".join(lines) + "\n"


def _format_finding_detail(finding: dict) -> str:
    lines: list[str] = []
    for key, label in [
        ("location", "Location"),
        ("vulnerability_class", "Vulnerability Class"),
        ("cwe_id", "CWE ID"),
        ("prerequisites", "Pre-requisites"),
        ("impact", "Impact"),
        ("severity", "Severity"),
        ("cvss_score", "CVSS Score"),
    ]:
        value = finding.get(key)
        if value:
            lines.append(f"- **{label}**: {_format_array_field(value)}")

    code_snippet = finding.get("code_snippet")
    if code_snippet:
        lines.append(f"- **Code snippet**:\n```\n{code_snippet}\n```")

    return "\n".join(lines)


def generate_report(
    research_record_path: str,
    findings_dir: str,
    output_path: str,
) -> GeneratedReportSummary:
    project_summary, threat_context = _parse_research_record(research_record_path)

    raw_findings: list[dict] = []
    for file_path in list_json_files_sync(findings_dir):
        finding = _parse_finding_file(file_path)
        if finding is not None:
            raw_findings.append(finding)

    raw_findings.sort(key=_severity_sort_key)

    severity_counts: dict[str, int] = {}
    for finding in raw_findings:
        sev = str(finding.get("severity", "Low"))
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    report: list[str] = []
    report.append("# Security Audit Report\n")
    report.append("## Project Summary\n")
    report.append((project_summary or "*(Project summary not available.)*") + "\n")
    report.append("## Threat Context\n")
    report.append((threat_context or "*(Threat context not available.)*") + "\n")
    report.append("## Findings Overview\n")
    report.append(f"**Total findings**: {len(raw_findings)}\n")
    for sev in ("Critical", "High", "Medium", "Low"):
        count = severity_counts.get(sev, 0)
        if count > 0:
            report.append(f"- **{sev}**: {count}")
    report.append("")
    report.append("## Findings Summary\n")
    report.append(_generate_summary_table(raw_findings))
    report.append("## Detailed Findings\n")

    if not raw_findings:
        report.append("No vulnerabilities were identified during this audit.\n")
    else:
        for finding in raw_findings:
            report.append("---\n")
            report.append(f"### {finding.get('id', 'N/A')}: {finding.get('title', 'N/A')}\n")
            detail = _format_finding_detail(finding)
            if detail:
                report.append(detail + "\n")

    Path(output_path).write_text("\n".join(report))
    return GeneratedReportSummary(total_findings=len(raw_findings), severity_counts=severity_counts)
