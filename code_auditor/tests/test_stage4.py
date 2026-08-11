from __future__ import annotations

import json
from pathlib import Path

from code_auditor.config import AuditConfig
from code_auditor.disclosures import build_dedupe_key
from code_auditor.stages import stage4


def _finding(**overrides: object) -> dict[str, object]:
    finding: dict[str, object] = {
        "id": "pending",
        "title": "Length underflow reaches memcpy",
        "location": "src/parser.c:parse_packet lines 10-24",
        "data_flow_trace": {
            "entry_point": "src/net.c:read_packet",
            "propagation_chain": ["buf + offset"],
            "neutralizing_checks": [],
            "sink": "memcpy(out, buf + offset, len - header_size)",
            "root_path": "src/parser.c",
        },
        "cwe_id": ["CWE-191"],
        "vulnerability_class": ["integer underflow"],
        "trigger": "Send a packet whose length is smaller than the header.",
    }
    finding.update(overrides)
    return finding


def _config(tmp_path: Path) -> tuple[AuditConfig, Path]:
    target = tmp_path / "target"
    output_dir = target / "audit-output"
    target.mkdir(parents=True)
    output_dir.mkdir()
    config = AuditConfig(
        target=str(target),
        output_dir=str(output_dir),
        max_parallel=1,
    )
    return config, output_dir


def _write_pending(output_dir: Path, name: str, finding: dict) -> Path:
    pending_dir = output_dir / "stage4-vulnerabilities" / "_pending"
    pending_dir.mkdir(parents=True, exist_ok=True)
    path = pending_dir / f"{name}.json"
    path.write_text(json.dumps(finding), encoding="utf-8")
    return path


def _write_final(output_dir: Path, vuln_id: str, finding: dict) -> Path:
    stage4_dir = output_dir / "stage4-vulnerabilities"
    stage4_dir.mkdir(parents=True, exist_ok=True)
    path = stage4_dir / f"{vuln_id}.json"
    path.write_text(json.dumps(finding), encoding="utf-8")
    return path


def test_deduplicates_same_vulnerability_different_severity(tmp_path: Path) -> None:
    """Two findings for the same vuln with different CVSS get one ID."""
    config, output_dir = _config(tmp_path)

    base = _finding()
    pending_critical = _write_pending(output_dir, "AU1-F-01", {**base, "cvss_score": 9.5})
    pending_high = _write_pending(output_dir, "AU2-F-03", {**base, "cvss_score": 7.5})

    result = stage4._assign_ids_and_finalize(
        [str(pending_critical), str(pending_high)], config
    )

    assert len(result) == 1
    # The Critical one (higher CVSS, sorted first) is kept → C-01
    assert result[0].endswith("C-01.json")
    # The duplicate pending file is deleted
    assert not pending_high.exists()


def test_keeps_distinct_vulnerabilities(tmp_path: Path) -> None:
    """Findings with different dedupe keys both get IDs."""
    config, output_dir = _config(tmp_path)

    finding_a = _finding(cvss_score=9.5)
    finding_b = _finding(
        cvss_score=7.5,
        location="src/crypto.c:verify_sig lines 5-12",
        trigger="Send a signature with invalid length.",
        data_flow_trace={
            "entry_point": "src/tls.c:recv_handshake",
            "propagation_chain": ["sig_len"],
            "neutralizing_checks": [],
            "sink": "memcmp(stored, sig, sig_len)",
            "root_path": "src/crypto.c",
        },
    )
    pending_a = _write_pending(output_dir, "AU1-F-01", finding_a)
    pending_b = _write_pending(output_dir, "AU2-F-01", finding_b)

    result = stage4._assign_ids_and_finalize(
        [str(pending_a), str(pending_b)], config
    )

    assert len(result) == 2
    assert any(p.endswith("C-01.json") for p in result)
    assert any(p.endswith("H-01.json") for p in result)


def test_deduplicates_against_existing_final(tmp_path: Path) -> None:
    """A pending finding that duplicates an existing finalized vuln is skipped."""
    config, output_dir = _config(tmp_path)

    _write_final(output_dir, "C-01", {**_finding(), "id": "C-01", "cvss_score": 9.5})
    pending = _write_pending(output_dir, "AU2-F-01", {**_finding(), "cvss_score": 7.5})

    result = stage4._assign_ids_and_finalize([str(pending)], config)

    # Only the existing C-01 remains; no new ID assigned
    assert len(result) == 1
    assert result[0].endswith("C-01.json")
    assert not pending.exists()


def test_dedupe_key_matches_for_same_vulnerability() -> None:
    """Sanity: same vuln with different id/cvss produces same dedupe key."""
    base = _finding()
    critical = {**base, "id": "C-01", "cvss_score": 9.5}
    high = {**base, "id": "H-08", "cvss_score": 7.5}

    assert build_dedupe_key(critical, "") == build_dedupe_key(high, "")
