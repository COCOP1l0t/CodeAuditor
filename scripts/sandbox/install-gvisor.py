#!/usr/bin/env python3
"""Stage a complete, checksum-verified gVisor release without configuring Docker."""
from __future__ import annotations

import argparse
import hashlib
import json
import platform
import re
import shutil
import sys
import tarfile
import tempfile
import urllib.request
from pathlib import Path, PurePosixPath

MAX_ARCHIVE_BYTES = 512 * 1024 * 1024
MAX_UNPACKED_BYTES = 1024 * 1024 * 1024


def release_url(version: str, architecture: str) -> str:
    if not re.fullmatch(r"latest|[0-9]{8}(?:\.[0-9]+)?", version):
        raise ValueError("version must be latest, YYYYMMDD, or YYYYMMDD.N")
    if architecture not in {"x86_64", "aarch64"}:
        raise ValueError("gVisor requires x86_64 or aarch64")
    return f"https://storage.googleapis.com/gvisor/releases/release/{version}/{architecture}"


def download(url: str, destination: Path, maximum: int) -> None:
    with urllib.request.urlopen(url, timeout=30) as response, destination.open("xb") as stream:
        if not response.geturl().startswith("https://storage.googleapis.com/gvisor/"):
            raise ValueError("unexpected release download redirect")
        count = 0
        while block := response.read(1024 * 1024):
            count += len(block)
            if count > maximum:
                raise ValueError("release download exceeds size limit")
            stream.write(block)


def verify_checksum(archive: Path, checksum_file: Path) -> str:
    # Read a digest, never execute checksum-file paths supplied by a server.
    lines = checksum_file.read_text(encoding="ascii").strip().splitlines()
    if len(lines) != 1:
        raise ValueError("expected one SHA-512 checksum")
    fields = lines[0].split()
    if not fields or not re.fullmatch(r"[0-9a-fA-F]{128}", fields[0]):
        raise ValueError("invalid SHA-512 checksum")
    with archive.open("rb") as stream:
        actual = hashlib.file_digest(stream, "sha512").hexdigest()
    if actual != fields[0].lower():
        raise ValueError("gVisor archive SHA-512 mismatch")
    return actual


def unpack_bundle(archive: Path, destination: Path) -> None:
    with tarfile.open(archive, "r:bz2") as bundle:
        members = bundle.getmembers()
        if len(members) > 4096 or sum(member.size for member in members) > MAX_UNPACKED_BYTES:
            raise ValueError("gVisor bundle exceeds extraction limits")
        names = set()
        for member in members:
            name = PurePosixPath(member.name)
            if name.is_absolute() or ".." in name.parts or not (member.isfile() or member.isdir()):
                raise ValueError("bundle must contain only relative regular files and directories")
            if str(name) in names:
                raise ValueError("duplicate bundle path")
            names.add(str(name))
        bundle.extractall(destination, members=members, filter="data")
    for filename in ("runsc", "containerd-shim-runsc-v1"):
        if not (destination / filename).is_file():
            raise ValueError(f"incomplete gVisor bundle: missing {filename}")
    sidecars = destination / "gvisor-bin"
    if not sidecars.is_dir() or not any(path.is_file() for path in sidecars.rglob("*")):
        raise ValueError("incomplete gVisor bundle: missing gvisor-bin sidecars")
    # runsc may re-execute as an unprivileged user; remove write permissions
    # for group/others while retaining world read/execute on shipped binaries.
    for path in [destination, *destination.rglob("*")]:
        path.chmod(0o755 if path.is_dir() or path.stat().st_mode & 0o111 else 0o644)
    for filename in ("runsc", "containerd-shim-runsc-v1"):
        (destination / filename).chmod(0o755)


def install_bundle(archive: Path, destination: Path, metadata: dict) -> None:
    if destination.exists() or destination.is_symlink():
        raise ValueError("destination already exists; use a new directory for an upgrade")
    destination.parent.mkdir(parents=True, mode=0o755, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=".gvisor-stage-", dir=destination.parent))
    try:
        unpack_bundle(archive, staging)
        (staging / "code-auditor-install.json").write_text(
            json.dumps(metadata, indent=2) + "\n", encoding="utf-8",
        )
        (staging / "code-auditor-install.json").chmod(0o644)
        if destination.exists() or destination.is_symlink():
            raise ValueError("destination appeared during installation")
        staging.rename(destination)
    finally:
        if staging.exists():
            shutil.rmtree(staging)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", default="latest", help="latest, YYYYMMDD, or YYYYMMDD.N")
    parser.add_argument("--destination", type=Path, default=Path("/opt/code-auditor/gvisor"))
    parser.add_argument("--archive", type=Path, help="use an already downloaded gvisor.tar.bz2")
    parser.add_argument("--sha512", type=Path, help="checksum file for --archive")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--apply", action="store_true", help="download and install the complete bundle")
    mode.add_argument("--dry-run", action="store_true", help="preview only (default)")
    args = parser.parse_args()
    try:
        if sys.version_info < (3, 12):
            raise ValueError("use Python 3.12 or newer, such as the CodeAuditor Python environment")
        if platform.system() != "Linux":
            raise ValueError("this installer targets Linux hosts")
        if bool(args.archive) != bool(args.sha512):
            raise ValueError("--archive and --sha512 must be supplied together")
        architecture = platform.machine()
        url = release_url(args.version, architecture)
        destination = args.destination.expanduser().absolute()
        print(f"Bundle: {args.archive or url + '/gvisor.tar.bz2'}")
        print(f"Install directory: {destination}")
        print("Verify SHA-512; install runsc, shim, and gvisor-bin together; do not change Docker.")
        if not args.apply:
            print("Preview only. Use --apply to install; /opt normally requires sudo.")
            return 0
        kernel = tuple(int(part) for part in platform.release().split(".")[:2])
        if kernel < (5, 6):
            raise ValueError("current gVisor releases require Linux 5.6 or newer")
        if destination.exists() or destination.is_symlink():
            raise ValueError("destination already exists; select a new installation directory")
        with tempfile.TemporaryDirectory(prefix="gvisor-download-") as directory:
            archive = args.archive or Path(directory) / "gvisor.tar.bz2"
            checksum = args.sha512 or Path(directory) / "gvisor.tar.bz2.sha512"
            if args.archive is None:
                download(url + "/gvisor.tar.bz2.sha512", checksum, 4096)
                download(url + "/gvisor.tar.bz2", archive, MAX_ARCHIVE_BYTES)
            digest = verify_checksum(archive, checksum)
            install_bundle(archive, destination, {
                "release": args.version, "architecture": architecture,
                "source": str(args.archive) if args.archive else url,
                "sha512": digest,
            })
        print(f"Installed runtime: {destination / 'runsc'}")
        print("Next: configure-gvisor.py --runsc <installed-runtime-path> (preview first).")
        return 0
    except (OSError, ValueError, tarfile.TarError) as exc:
        parser.exit(1, f"gVisor installation failed: {exc}\n")


if __name__ == "__main__":
    raise SystemExit(main())
