from __future__ import annotations

import asyncio
import json
import os
import tempfile

import pytest

from code_auditor.checkpoint import CheckpointManager
from code_auditor.config import AnalysisUnit, AuditConfig
from code_auditor.parsing.stage2 import parse_au_files, parse_auditing_focus
from code_auditor.prompts import load_prompt
from code_auditor.stages import stage3
from code_auditor.stages import stage4
from code_auditor.validation.stage2 import (
    validate_stage2_au_file,
    validate_stage2_dir,
    validate_triage_file,
)
from code_auditor.validation.stage4 import validate_stage4_file
from code_auditor.validation.stage6 import validate_stage6_disclosure


def _write_au(path: str, desc: str, files: list[str], focus: str) -> None:
    with open(path, "w") as f:
        json.dump({"description": desc, "files": files, "focus": focus}, f)


def _write_triage(result_dir: str, entries: list[dict]) -> None:
    with open(os.path.join(result_dir, "triage.json"), "w") as f:
        json.dump(entries, f)


def _make_triage_entry(area: str, files: list[str], selected: bool) -> dict:
    return {
        "area": area,
        "files": files,
        "loc": 100,
        "rationale": f"{'Selected' if selected else 'Excluded'} for testing.",
        "selected": selected,
    }


def test_stage2_parser_reads_au_files():
    with tempfile.TemporaryDirectory() as tmp:
        _write_au(os.path.join(tmp, "AU-1.json"), "Parses raw DHCP packets", ["src/parser/parse.c", "src/parser/options.c"], "Trace len field through parse_options().")
        _write_au(os.path.join(tmp, "AU-2.json"), "Session management", ["src/session.c"], "Check state transitions.")

        units = parse_au_files(tmp)
        assert len(units) == 2
        assert units[0].id == "AU-1"
        assert units[1].id == "AU-2"


def test_stage2_validator_accepts_valid_au_file():
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "AU-1.json")
        _write_au(path, "Parses raw DHCP packets from the network", ["src/parser/parse.c", "src/parser/options.c"], "Trace the len field from the packet header through parse_options().")

        assert validate_stage2_au_file(path) == []


def test_stage2_validator_rejects_empty_fields():
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "AU-1.json")
        with open(path, "w") as f:
            json.dump({"description": "", "files": [], "focus": ""}, f)

        issues = validate_stage2_au_file(path)
        assert len(issues) == 3  # description, files, focus all blank


def test_stage2_dir_validator_checks_sequential_ids():
    with tempfile.TemporaryDirectory() as tmp:
        _write_triage(tmp, [_make_triage_entry("area1", ["a.c"], True)])
        # Write AU-1 and AU-3 (skipping AU-2)
        for n in (1, 3):
            _write_au(os.path.join(tmp, f"AU-{n}.json"), "d", ["a.c"], "f")

        issues = validate_stage2_dir(tmp)
        seq_issues = [i for i in issues if "Non-sequential" in i.description]
        assert len(seq_issues) == 1


def test_stage2_dir_validator_rejects_too_many_aus():
    # Use max_aus=4 so hard limit is 6; create 7 to exceed it
    max_aus = 4
    count = max_aus + max_aus // 2 + 1  # 7, exceeds hard limit of 6
    with tempfile.TemporaryDirectory() as tmp:
        entries = [_make_triage_entry(f"area{n}", ["a.c"], True) for n in range(1, count + 1)]
        _write_triage(tmp, entries)
        for n in range(1, count + 1):
            _write_au(os.path.join(tmp, f"AU-{n}.json"), "d", ["a.c"], "f")

        issues = validate_stage2_dir(tmp, max_aus=max_aus)
        too_many_au = [i for i in issues if "Too many analysis units" in i.description]
        too_many_triage = [i for i in issues if "too many areas selected" in i.description]
        assert len(too_many_au) == 1
        assert len(too_many_triage) == 1


def test_stage2_dir_validator_checks_triage_json():
    with tempfile.TemporaryDirectory() as tmp:
        _write_au(os.path.join(tmp, "AU-1.json"), "d", ["a.c"], "f")
        # No triage.json — should produce a validation issue
        issues = validate_stage2_dir(tmp)
        triage_issues = [i for i in issues if "triage.json" in i.description]
        assert len(triage_issues) == 1


def test_triage_validator_accepts_valid():
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "triage.json")
        with open(path, "w") as f:
            json.dump([
                _make_triage_entry("Parsing", ["src/parse.c"], True),
                _make_triage_entry("Config", ["src/config.c"], False),
            ], f)

        assert validate_triage_file(path) == []


def test_triage_validator_rejects_missing_fields():
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "triage.json")
        with open(path, "w") as f:
            json.dump([{"area": "Parsing"}], f)  # missing files, rationale, selected

        issues = validate_triage_file(path)
        assert len(issues) == 3  # files, rationale, selected


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


def test_stage4_validator_accepts_valid_finding():
    with tempfile.TemporaryDirectory() as tmp:
        finding_path = os.path.join(tmp, "H-01.json")
        with open(finding_path, "w") as f:
            json.dump({
                "id": "H-01",
                "title": "Length underflow reaches memcpy",
                "location": "src/parser.c:parse_packet (lines 10-24)",
                "data_flow_trace": {
                    "entry_point": "net/recv() in src/net.c:read_packet()",
                    "propagation_chain": [
                        "read_packet() passes raw bytes to parse_packet() as buf param",
                        "parse_packet() reads 2-byte length field from buf into uint16_t len",
                        "len is subtracted by header_size without underflow check, result passed to memcpy as size",
                    ],
                    "neutralizing_checks": "none",
                    "sink": "memcpy(out, buf + offset, len - header_size) in parse_packet():L22",
                },
                "cwe_id": ["CWE-191"],
                "vulnerability_class": ["integer underflow"],
                "cvss_score": "8.1",
                "severity": "High",
                "trigger": "Send a crafted packet with a 2-byte length field smaller than header_size, causing an integer underflow in the memcpy size argument",
                "prerequisites": "Default configuration",
                "impact": "DoS",
                "code_snippet": "memcpy(...)",
            }, f)

        assert validate_stage4_file(finding_path) == []


def test_stage4_validator_rejects_missing_data_flow_trace():
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "H-01.json")
        with open(path, "w") as f:
            json.dump({
                "id": "H-01",
                "title": "Test finding",
                "location": "src/foo.c:bar()",
                "cwe_id": ["CWE-120"],
                "vulnerability_class": ["buffer overflow"],
                "cvss_score": "7.5",
            }, f)

        issues = validate_stage4_file(path)
        missing = [i for i in issues if "data_flow_trace" in i.description]
        assert len(missing) == 1


def test_stage4_validator_rejects_malformed_data_flow_trace():
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "H-01.json")
        # data_flow_trace is a string instead of an object
        with open(path, "w") as f:
            json.dump({
                "id": "H-01",
                "title": "Test finding",
                "location": "src/foo.c:bar()",
                "data_flow_trace": "not an object",
                "cwe_id": ["CWE-120"],
                "vulnerability_class": ["buffer overflow"],
                "cvss_score": "7.5",
            }, f)

        issues = validate_stage4_file(path)
        type_issues = [i for i in issues if "must be a JSON object" in i.description]
        assert len(type_issues) == 1


def test_stage4_validator_rejects_missing_trace_subfields():
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "H-01.json")
        # data_flow_trace is an object but missing all subfields
        with open(path, "w") as f:
            json.dump({
                "id": "H-01",
                "title": "Test finding",
                "location": "src/foo.c:bar()",
                "data_flow_trace": {},
                "cwe_id": ["CWE-120"],
                "vulnerability_class": ["buffer overflow"],
                "cvss_score": "7.5",
            }, f)

        issues = validate_stage4_file(path)
        subfield_issues = [i for i in issues if "data_flow_trace" in i.description and "missing" in i.description]
        assert len(subfield_issues) == 4  # entry_point, propagation_chain, neutralizing_checks, sink


def test_stage4_validator_rejects_non_array_propagation_chain():
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "H-01.json")
        with open(path, "w") as f:
            json.dump({
                "id": "H-01",
                "title": "Test finding",
                "location": "src/foo.c:bar()",
                "data_flow_trace": {
                    "entry_point": "input",
                    "propagation_chain": "not an array",
                    "neutralizing_checks": "none",
                    "sink": "output",
                },
                "cwe_id": ["CWE-120"],
                "vulnerability_class": ["buffer overflow"],
                "cvss_score": "7.5",
            }, f)

        issues = validate_stage4_file(path)
        chain_issues = [i for i in issues if "propagation_chain" in i.description and "array" in i.description]
        assert len(chain_issues) == 1


def test_stage6_prompt_requires_target_guidelines_security_rationale() -> None:
    prompt = load_prompt("stage6.md", {
        "vuln_report_path": "/tmp/report.md",
        "poc_dir": "/tmp/poc",
        "finding_reference": "Finding context",
        "target_path": "/tmp/target",
        "disclosure_dir": "/tmp/disclosure",
        "vuln_id": "H-01",
        "wiki_context": "No wiki context.",
    })

    assert "Why This Is a Security Issue" in prompt
    assert "target security guidelines" in prompt.lower()
    assert "maintainer" in prompt.lower()


def test_stage6_validator_rejects_report_missing_security_rationale_section() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        report_path = os.path.join(tmp, "report.md")
        with open(report_path, "w", encoding="utf-8") as f:
            f.write(
                "# Report\n\n"
                "## Summary\n\nSummary text.\n\n"
                "## Severity Assessment\n\nHigh.\n\n"
                "## Security Impact\n\nImpact text.\n\n"
                "## Root Cause\n\nRoot cause text.\n\n"
                "## Reproduction\n\nSteps.\n"
            )
        with open(os.path.join(tmp, "email.txt"), "w", encoding="utf-8") as f:
            f.write("Subject: [Security] Test\n")
        with open(os.path.join(tmp, "disclosure.zip"), "wb") as f:
            f.write(b"zip")

        issues = validate_stage6_disclosure(tmp)

    missing = [
        issue for issue in issues
        if "Why This Is a Security Issue" in issue.description
    ]
    assert len(missing) == 1


def test_stage4_finalize_skips_invalid_pending_file() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        pending_dir = os.path.join(tmp, "stage4-vulnerabilities", "_pending")
        os.makedirs(pending_dir)
        pending_path = os.path.join(pending_dir, "AU-1-F-1.json")
        with open(pending_path, "w") as f:
            json.dump({
                "id": "pending",
                "title": "Invalid evaluated finding",
                "location": "src/foo.c:bar()",
                "cwe_id": ["CWE-120"],
                "vulnerability_class": ["buffer overflow"],
                "trigger": "crafted input",
                "cvss_score": "7.5",
            }, f)

        config = AuditConfig(target=tmp, output_dir=tmp)

        assert stage4._assign_ids_and_finalize([pending_path], config) == []
        assert os.path.exists(pending_path)
        assert not os.path.exists(os.path.join(tmp, "stage4-vulnerabilities", "H-01.json"))


def test_stage4_finalize_ignores_malformed_existing_id() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        stage4_dir = os.path.join(tmp, "stage4-vulnerabilities")
        pending_dir = os.path.join(stage4_dir, "_pending")
        os.makedirs(pending_dir)

        with open(os.path.join(stage4_dir, "bad.json"), "w") as f:
            json.dump({"id": "H-not-a-number"}, f)

        pending_path = os.path.join(pending_dir, "AU-1-F-1.json")
        with open(pending_path, "w") as f:
            json.dump({
                "id": "pending",
                "title": "Valid evaluated finding",
                "location": "src/foo.c:bar()",
                "data_flow_trace": {
                    "entry_point": "input",
                    "propagation_chain": ["input reaches sink"],
                    "neutralizing_checks": "none",
                    "sink": "sink",
                },
                "cwe_id": ["CWE-120"],
                "vulnerability_class": ["buffer overflow"],
                "trigger": "crafted input",
                "cvss_score": "7.5",
            }, f)

        config = AuditConfig(target=tmp, output_dir=tmp)

        finalized = stage4._assign_ids_and_finalize([pending_path], config)

        assert os.path.join(stage4_dir, "H-01.json") in finalized


def test_stage4_run_finding_does_not_checkpoint_invalid_pending_file(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def run_case() -> None:
        with tempfile.TemporaryDirectory() as tmp:
            target = os.path.join(tmp, "target")
            output_dir = os.path.join(tmp, "audit-output")
            pending_dir = os.path.join(output_dir, "stage4-vulnerabilities", "_pending")
            os.makedirs(target)
            os.makedirs(pending_dir)

            stage3_finding = os.path.join(tmp, "AU-1-F-1.json")
            with open(stage3_finding, "w") as f:
                json.dump({"finding_id": "AU-1-F-1"}, f)

            pending_path = os.path.join(pending_dir, "AU-1-F-1.json")

            async def fake_run_agent(*_args, **_kwargs) -> str:  # type: ignore[no-untyped-def]
                with open(pending_path, "w") as f:
                    json.dump({
                        "id": "pending",
                        "title": "Invalid evaluated finding",
                        "location": "src/foo.c:bar()",
                        "cwe_id": ["CWE-120"],
                        "vulnerability_class": ["buffer overflow"],
                        "trigger": "crafted input",
                        "cvss_score": "7.5",
                    }, f)
                return ""

            monkeypatch.setattr(stage4, "run_agent", fake_run_agent)

            config = AuditConfig(target=target, output_dir=output_dir)
            checkpoint = CheckpointManager(output_dir, resume=True)

            result = await stage4._run_finding(
                stage3_finding,
                config,
                checkpoint,
                os.path.join(tmp, "vulnerability-criteria.md"),
            )

            assert result is None
            assert not checkpoint.is_complete("stage4:AU-1-F-1.json")
            assert not os.path.exists(pending_path)

    asyncio.run(run_case())


def test_stage4_backfill_only_marks_exact_pending_findings() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        pending_dir = os.path.join(tmp, "stage4-vulnerabilities", "_pending")
        os.makedirs(pending_dir)
        au1 = os.path.join(tmp, "AU-1-F-1.json")
        au2 = os.path.join(tmp, "AU-2-F-1.json")
        for path in (au1, au2):
            with open(path, "w") as f:
                json.dump({"finding_id": os.path.splitext(os.path.basename(path))[0]}, f)
        with open(os.path.join(pending_dir, "AU-2-F-1.json"), "w") as f:
            json.dump({"id": "pending"}, f)

        config = AuditConfig(target=tmp, output_dir=tmp)
        checkpoint = CheckpointManager(tmp, resume=True)

        stage4._backfill_stage4_markers([au1, au2], config, checkpoint)

        assert not os.path.exists(checkpoint._marker_path("stage4:AU-1-F-1.json"))
        assert os.path.exists(checkpoint._marker_path("stage4:AU-2-F-1.json"))


def test_stage3_run_unit_does_not_checkpoint_invalid_finding(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def run_case() -> None:
        with tempfile.TemporaryDirectory() as tmp:
            target = os.path.join(tmp, "target")
            output_dir = os.path.join(tmp, "audit-output")
            stage2_dir = os.path.join(output_dir, "stage2-analysis-units")
            findings_dir = os.path.join(output_dir, "stage3-findings")
            os.makedirs(target)
            os.makedirs(stage2_dir)
            os.makedirs(findings_dir)

            au_path = os.path.join(stage2_dir, "AU-1.json")
            with open(au_path, "w") as f:
                json.dump({"description": "d", "files": ["a.c"], "focus": "f"}, f)

            finding_path = os.path.join(findings_dir, "AU-1-F-1.json")

            async def fake_run_agent(*_args, **_kwargs) -> str:  # type: ignore[no-untyped-def]
                with open(finding_path, "w") as f:
                    json.dump({
                        "finding_id": "AU-1-F-1",
                        "title": "Invalid finding",
                    }, f)
                return ""

            monkeypatch.setattr(stage3, "run_agent", fake_run_agent)

            config = AuditConfig(target=target, output_dir=output_dir)
            checkpoint = CheckpointManager(output_dir, resume=True)
            unit = AnalysisUnit(id="AU-1", au_file_path=au_path)

            result = await stage3._run_unit(
                unit,
                config,
                checkpoint,
                os.path.join(tmp, "auditing-focus.md"),
                os.path.join(tmp, "vulnerability-criteria.md"),
            )

            assert result == []
            assert not checkpoint.is_complete("stage3:AU-1")
            assert not os.path.exists(finding_path)

    asyncio.run(run_case())
