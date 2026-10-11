from pathlib import Path
import hashlib

import pytest

from code_auditor.retention import RetentionError, validate_retain_manifest_data


def test_manifest_v2_windows_powershell_entrypoint(tmp_path: Path) -> None:
    script = tmp_path / "reproduce.ps1"
    script.write_text("Write-Output 'reproduced'\n", encoding="utf-8")
    report = tmp_path / "report.md"
    report.write_text("# Report\n", encoding="utf-8")

    manifest = validate_retain_manifest_data(
        tmp_path,
        {
            "schema_version": 2,
            "entrypoint": {
                "path": "reproduce.ps1",
                "platform": "windows",
                "interpreter": "powershell",
                "argv": ["-NoProfile"],
            },
            "files": [
                {
                    "path": "report.md",
                    "role": "report",
                    "size": report.stat().st_size,
                    "sha256": hashlib.sha256(report.read_bytes()).hexdigest(),
                },
                {
                    "path": "reproduce.ps1",
                    "role": "entrypoint",
                    "size": script.stat().st_size,
                    "sha256": hashlib.sha256(script.read_bytes()).hexdigest(),
                },
            ],
        },
    )

    assert manifest.schema_version == 2
    assert manifest.platform == "windows"
    assert manifest.interpreter == "powershell"
    assert manifest.entrypoint == "reproduce.ps1"
    assert manifest.argv == ("-NoProfile",)


def test_manifest_v2_rejects_content_mutation(tmp_path: Path) -> None:
    script = tmp_path / "reproduce.ps1"
    script.write_text("Write-Output 'first'\n", encoding="utf-8")
    digest = hashlib.sha256(script.read_bytes()).hexdigest()
    size = script.stat().st_size
    script.write_text("Write-Output 'other'\n", encoding="utf-8")

    with pytest.raises(RetentionError, match="SHA-256 mismatch"):
        validate_retain_manifest_data(
            tmp_path,
            {
                "schema_version": 2,
                "entrypoint": {
                    "path": "reproduce.ps1",
                    "platform": "windows",
                    "interpreter": "powershell",
                },
                "files": [
                    {
                        "path": "reproduce.ps1",
                        "role": "entrypoint",
                        "size": size,
                        "sha256": digest,
                    }
                ],
            },
        )
