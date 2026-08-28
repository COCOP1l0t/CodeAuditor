"""Native local-directory selection for the Web UI.

The Web frontend cannot learn an absolute filesystem path from a normal HTML
directory input. CodeAuditor runs on the same machine as the browser, so a
small platform-native chooser can select a server-local audit target.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys


class LocalDirectoryPickerError(RuntimeError):
    """Raised when a local directory cannot be selected or validated."""


class LocalDirectoryPickerUnavailable(LocalDirectoryPickerError):
    """Raised when no native directory picker is available."""


def validate_local_audit_target(path: str) -> str:
    """Return a canonical, readable local audit directory."""
    if not isinstance(path, str) or not path or "\x00" in path:
        raise LocalDirectoryPickerError("The selected local folder is invalid.")
    expanded = os.path.expanduser(path.strip())
    if not os.path.isabs(expanded):
        raise LocalDirectoryPickerError("The selected local folder must be absolute.")
    resolved = os.path.realpath(expanded)
    if os.path.dirname(resolved) == resolved:
        raise LocalDirectoryPickerError(
            "The filesystem root cannot be used as an audit target."
        )
    if not os.path.isdir(resolved):
        raise LocalDirectoryPickerError(
            "The selected local folder no longer exists or is not a directory."
        )
    if not os.access(resolved, os.R_OK | os.X_OK):
        raise LocalDirectoryPickerError("The selected local folder is not readable.")
    return resolved


def choose_local_directory() -> str | None:
    """Open the host's native folder chooser and return its canonical path.

    ``None`` means the user cancelled the dialog. The function is blocking and
    should be called through ``asyncio.to_thread`` by an async Web endpoint.
    """
    if sys.platform == "darwin":
        command = [
            "osascript",
            "-e",
            'POSIX path of (choose folder with prompt "Select a local code folder to audit")',
        ]
    elif os.name == "nt":
        powershell = shutil.which("powershell.exe") or shutil.which("pwsh.exe")
        if not powershell:
            raise LocalDirectoryPickerUnavailable(
                "No native folder picker is available on this system."
            )
        script = (
            "Add-Type -AssemblyName System.Windows.Forms; "
            "$dialog = New-Object System.Windows.Forms.FolderBrowserDialog; "
            "$dialog.Description = 'Select a local code folder to audit'; "
            "if ($dialog.ShowDialog() -eq 'OK') { $dialog.SelectedPath }"
        )
        command = [powershell, "-NoProfile", "-Command", script]
    else:
        zenity = shutil.which("zenity")
        kdialog = shutil.which("kdialog")
        if zenity:
            command = [
                zenity,
                "--file-selection",
                "--directory",
                "--title=Select a local code folder to audit",
            ]
        elif kdialog:
            command = [
                kdialog,
                "--getexistingdirectory",
                os.getcwd(),
                "--title",
                "Select a local code folder to audit",
            ]
        else:
            raise LocalDirectoryPickerUnavailable(
                "No native folder picker is available. Install zenity or kdialog."
            )

    try:
        result = subprocess.run(command, capture_output=True, text=True, check=False)
    except OSError as exc:
        raise LocalDirectoryPickerUnavailable(
            f"Could not open the native folder picker: {exc}"
        ) from exc
    if result.returncode != 0:
        # Native pickers use a non-zero exit status for Cancel.
        return None
    selected = result.stdout.strip()
    if not selected:
        return None
    return validate_local_audit_target(selected)
