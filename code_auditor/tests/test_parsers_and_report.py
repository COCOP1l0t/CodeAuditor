from __future__ import annotations

import json
import os
import tempfile

from code_auditor.parsing.stage2 import parse_au_files, parse_auditing_focus
from code_auditor.report.generate import generate_report
from code_auditor.validation.stage2 import validate_stage2_au_file, validate_stage2_dir
from code_auditor.validation.stage4 import validate_stage4_file


def test_stage2_parser_reads_au_files():
    with tempfile.TemporaryDirectory() as tmp:
        for i, (desc, files, focus, analyze) in enumerate([
            ("Parses raw DHCP packets", ["src/parser/parse.c", "src/parser/options.c"], "Trace len field through parse_options().", True),
            ("Configuration loading", ["src/config.c"], "Check file path handling.", False),
        ], start=1):
            path = os.path.join(tmp, f"AU-{i}.json")
            with open(path, "w") as f:
                json.dump({"description": desc, "files": files, "focus": focus, "analyze": analyze}, f)

        # only_analyze=True: should return only the first AU
        units = parse_au_files(tmp, only_analyze=True)
        assert len(units) == 1
        assert units[0].id == "AU-1"

        # only_analyze=False: should return both
        all_units = parse_au_files(tmp, only_analyze=False)
        assert len(all_units) == 2


def test_stage2_validator_accepts_valid_au_file():
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "AU-1.json")
        with open(path, "w") as f:
            json.dump({
                "description": "Parses raw DHCP packets from the network",
                "files": ["src/parser/parse.c", "src/parser/options.c"],
                "focus": "Trace the len field from the packet header through parse_options().",
                "analyze": True,
            }, f)

        assert validate_stage2_au_file(path) == []


def test_stage2_validator_rejects_empty_fields():
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "AU-1.json")
        with open(path, "w") as f:
            json.dump({"description": "", "files": [], "focus": "", "analyze": True}, f)

        issues = validate_stage2_au_file(path)
        assert len(issues) == 3  # description, files, focus all blank


def test_stage2_validator_rejects_missing_analyze():
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "AU-1.json")
        with open(path, "w") as f:
            json.dump({"description": "desc", "files": ["a.c"], "focus": "focus"}, f)

        issues = validate_stage2_au_file(path)
        assert len(issues) == 1
        assert "analyze" in issues[0].description


def test_stage2_dir_validator_checks_sequential_ids():
    with tempfile.TemporaryDirectory() as tmp:
        # Write AU-1 and AU-3 (skipping AU-2)
        for n in (1, 3):
            path = os.path.join(tmp, f"AU-{n}.json")
            with open(path, "w") as f:
                json.dump({"description": "d", "files": ["a.c"], "focus": "f", "analyze": True}, f)

        issues = validate_stage2_dir(tmp)
        seq_issues = [i for i in issues if "sequential" in i.description.lower() or "Non-sequential" in i.description]
        assert len(seq_issues) == 1


def test_stage2_dir_validator_rejects_too_many_analyze():
    with tempfile.TemporaryDirectory() as tmp:
        for n in range(1, 53):  # 52 AUs all with analyze: true
            path = os.path.join(tmp, f"AU-{n}.json")
            with open(path, "w") as f:
                json.dump({"description": "d", "files": ["a.c"], "focus": "f", "analyze": True}, f)

        issues = validate_stage2_dir(tmp)
        too_many = [i for i in issues if "Too many" in i.description]
        assert len(too_many) == 1


def test_parse_auditing_focus_extracts_sections():
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "auditing-focus.md")
        with open(path, "w") as f:
            f.write(
                "# Auditing Focus\n\n"
                "## Explicit In-Scope and Out-of-Scope Modules\n\n"
                "In scope: parser, network\nOut of scope: tests\n\n"
                "## Historical Hot Spots\n\n"
                "- CVE-2024-1234 in parser\n"
            )

        scope, hot_spots = parse_auditing_focus(path)
        assert "parser" in scope
        assert "Out of scope" in scope
        assert "CVE-2024-1234" in hot_spots


def test_parse_auditing_focus_handles_missing_file():
    scope, hot_spots = parse_auditing_focus("/nonexistent/path.md")
    assert scope == ""
    assert hot_spots == ""


def test_stage4_validator_and_report_generator_accept_json():
    with tempfile.TemporaryDirectory() as tmp:
        stage1_dir = os.path.join(tmp, "stage-1-details")
        os.makedirs(stage1_dir)
        research_record_path = os.path.join(stage1_dir, "stage-1-security-context.json")
        findings_dir = os.path.join(tmp, "stage-4-details")
        report_path = os.path.join(tmp, "report.md")
        finding_path = os.path.join(findings_dir, "H-01.json")

        os.makedirs(findings_dir)
        with open(research_record_path, "w") as f:
            json.dump({
                "project": {
                    "name": "Example Protocol",
                    "path": "/tmp/example",
                    "language": "C",
                    "description": "Example protocol implementation.",
                    "deployment_model": "Network daemon",
                },
                "sources_consulted": [],
                "scope_announcements": {
                    "in_scope_modules": [],
                    "out_of_scope_modules": [],
                    "in_scope_issue_types": ["memory corruption"],
                    "out_of_scope_issue_types": ["test code"],
                },
                "historical_vulnerabilities": [
                    {
                        "cve_id": "CVE-2024-1234",
                        "date": "2024-01-15",
                        "affected_component": "parser",
                        "vulnerability_class": "buffer overflow",
                        "root_cause": "Missing bounds check",
                        "impact": "RCE",
                        "severity": "Critical",
                        "attacker_profile": "Network attacker",
                        "summary": "Heap buffer overflow in protocol parser.",
                    },
                ],
                "severity_guidance": {
                    "source": "SECURITY.md",
                    "raw_quotes": [],
                    "notes": "Memory corruption in parsers is Critical.",
                },
                "fuzzing_targets": [],
                "notes": "",
            }, f)
        with open(finding_path, "w") as f:
            json.dump({
                "id": "H-01",
                "title": "Length underflow reaches memcpy",
                "location": "src/parser.c:parse_packet (lines 10-24)",
                "cwe_id": ["CWE-191"],
                "vulnerability_class": ["integer underflow"],
                "cvss_score": "8.1",
                "severity": "High",
                "prerequisites": "Default configuration",
                "impact": "DoS",
                "code_snippet": "memcpy(...)",
            }, f)

        assert validate_stage4_file(finding_path) == []

        summary = generate_report(research_record_path, findings_dir, report_path)
        report_content = open(report_path).read()

        assert summary.total_findings == 1
        assert "H-01: Length underflow reaches memcpy" in report_content
        assert "Example Protocol" in report_content
        assert "CVE-2024-1234" in report_content
