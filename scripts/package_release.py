#!/usr/bin/env python3
"""Package a native release build and run the extracted binary before upload."""

import argparse
import hashlib
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import tempfile
import zipfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    for value in (args.target, args.version):
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", value):
            parser.error("target and version must be safe archive name components")

    root = Path(__file__).resolve().parent.parent
    executable = "xboard-snell.exe" if "windows" in args.target else "xboard-snell"
    binary = root / "target" / args.target / "release" / executable
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    name = f"xboard-snell-{args.version}-{args.target}"
    windows = "windows" in args.target
    archive = output / (name + (".zip" if windows else ".tar.gz"))

    with tempfile.TemporaryDirectory() as temporary:
        staging = Path(temporary) / name
        staging.mkdir()
        shutil.copy2(binary, staging / executable)
        (staging / executable).chmod(0o755)
        for source, destination in [
            ("config.example.toml", "config.example.toml"),
            ("config.multi-node.example.toml", "config.multi-node.example.toml"),
            ("README.md", "README.md"),
            ("scripts/install.sh", "scripts/install.sh"),
            ("systemd/xboard-snell.service", "systemd/xboard-snell.service"),
            ("snell/LICENSE", "LICENSE"),
            ("snell/UPSTREAM.md", "snell/UPSTREAM.md"),
            ("docs/multi-psk-validation.md", "docs/multi-psk-validation.md"),
            ("docs/upgrading.md", "docs/upgrading.md"),
            ("docs/xboard-v2-update-guide.md", "docs/xboard-v2-update-guide.md"),
        ]:
            (staging / destination).parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(root / source, staging / destination)
        release_notes = root / f"RELEASE_NOTES_{args.version}.md"
        if release_notes.is_file():
            shutil.copy2(release_notes, staging / release_notes.name)
        if windows:
            with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as package:
                for member in sorted(staging.rglob("*")):
                    if not member.is_file():
                        continue
                    package.write(member, arcname=f"{name}/{member.relative_to(staging).as_posix()}")
        else:
            with tarfile.open(archive, "w:gz") as package:
                package.add(staging, arcname=name)

        extracted = Path(temporary) / "extracted"
        if windows:
            with zipfile.ZipFile(archive) as package:
                package.extractall(extracted)
        else:
            with tarfile.open(archive) as package:
                package.extractall(extracted, filter="data")
        directory = extracted / name
        command = [str(directory / executable)]
        subprocess.run(command + ["--version"], cwd=directory, check=True, timeout=30)
        for config in ("config.example.toml", "config.multi-node.example.toml"):
            subprocess.run(command + ["--check", "-c", config],
                           cwd=directory, check=True, timeout=30)

    if "linux-musl" in args.target:
        # A directly runnable Linux release must not depend on a host ELF interpreter.
        elf = subprocess.run(["readelf", "-l", str(binary)], check=True, capture_output=True, text=True)
        if "INTERP" in elf.stdout:
            raise RuntimeError("musl binary unexpectedly needs a dynamic ELF interpreter")
    checksum = hashlib.sha256(archive.read_bytes()).hexdigest()
    archive.with_name(archive.name + ".sha256").write_text(f"{checksum}  {archive.name}\n", encoding="utf-8", newline="\n")
    print(f"Verified {archive.name} ({archive.stat().st_size:,} bytes)")


if __name__ == "__main__":
    main()
