#!/usr/bin/env python3
"""Build an allowlisted public download site from verified private release assets."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parent.parent
TARGETS = {
    "linux": {"x64": "x86_64-unknown-linux-musl", "arm64": "aarch64-unknown-linux-musl"},
    "macos": {"x64": "x86_64-apple-darwin", "arm64": "aarch64-apple-darwin"},
    "win": {"x64": "x86_64-pc-windows-msvc", "arm64": "aarch64-pc-windows-msvc"},
}
MAX_FILE_SIZE = 25 * 1024 * 1024


def safe_tag(tag):
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", tag):
        raise ValueError(f"Invalid release tag: {tag!r}")
    return tag


def asset_info(path, url):
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"Missing regular release file: {path.name}")
    size = path.stat().st_size
    if size > MAX_FILE_SIZE:
        raise ValueError(f"Pages limits individual files to 25 MiB: {path.name}")
    return {"url": url, "sha256": hashlib.sha256(path.read_bytes()).hexdigest(), "size": size}


def gh_json(*args):
    response = subprocess.run(["gh", *args], check=True, capture_output=True, text=True, timeout=60)
    return json.loads(response.stdout)


def download_releases(repository, version, destination, keep):
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository):
        raise ValueError("Invalid GitHub repository")
    view = ["release", "view"] + ([] if version == "latest" else [safe_tag(version)])
    selected = gh_json(*view, "--repo", repository, "--json", "tagName,body,isDraft,isPrerelease")
    if selected["isDraft"] or selected["isPrerelease"]:
        raise ValueError("The public stable channel requires a published, non-prerelease release")
    latest = safe_tag(selected["tagName"])
    recent = gh_json("release", "list", "--repo", repository, "--limit", str(keep),
                     "--exclude-drafts", "--exclude-pre-releases", "--json", "tagName")
    tags = list(dict.fromkeys([latest] + [safe_tag(item["tagName"]) for item in recent]))[:keep]
    for tag in tags:
        directory = destination / tag
        directory.mkdir(parents=True)
        metadata = selected if tag == latest else gh_json(
            "release", "view", tag, "--repo", repository, "--json", "tagName,body,isDraft,isPrerelease")
        (directory / "release.json").write_text(json.dumps(metadata), encoding="utf-8")
        subprocess.run([
            "gh", "release", "download", tag, "--repo", repository, "--dir", str(directory),
            "--pattern", f"xboard-snell-{tag}-*.tar.gz", "--pattern", f"xboard-snell-{tag}-*.zip",
            "--pattern", "SHA256SUMS",
        ], check=True, timeout=300)
    return latest


def release_manifest(directory, base_url):
    tag = safe_tag(directory.name)
    if directory.is_symlink():
        raise ValueError("Release directories must not be symbolic links")
    metadata = json.loads((directory / "release.json").read_text(encoding="utf-8"))
    if metadata["tagName"] != tag or metadata["isDraft"] or metadata["isPrerelease"]:
        raise ValueError(f"Invalid stable release metadata: {tag}")
    sums = {}
    sums_path = directory / "SHA256SUMS"
    if sums_path.is_symlink():
        raise ValueError("Checksum files must not be symbolic links")
    for line in sums_path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        digest, name = line.split()
        if not re.fullmatch(r"[a-fA-F0-9]{64}", digest) or name in sums:
            raise ValueError(f"Invalid or duplicate checksum in {tag}")
        sums[name] = digest.lower()
    version = tag.removeprefix("v")
    manifest = {"schemaVersion": 1, "version": version, "tag": tag, "notes": metadata["body"]}
    files = []
    for platform, architectures in TARGETS.items():
        manifest[platform] = {"version": version}
        for architecture, target in architectures.items():
            extension = "zip" if platform == "win" else "tar.gz"
            name = f"xboard-snell-{tag}-{target}.{extension}"
            path = directory / name
            url = f"{base_url}/xboard-snell/releases/{tag}/{name}"
            info = asset_info(path, url)
            if info["sha256"] != sums.get(name):
                raise ValueError(f"Release checksum mismatch: {name}")
            manifest[platform][architecture] = info
            files.append((path, name, info))
    manifest.update(manifest["linux"]["x64"])
    return manifest, files


def build_site(assets, version, base_url, output):
    parsed = urlsplit(base_url)
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password
            or parsed.query or parsed.fragment or parsed.path not in ("", "/")):
        raise ValueError("Base URL must be an HTTPS origin without credentials, query or fragment")
    base_url = base_url.rstrip("/")
    safe_tag(version)
    if output.exists():
        raise ValueError("Output directory must not already exist")
    releases = {}
    for directory in sorted(assets.iterdir()):
        if directory.is_dir():
            releases[directory.name] = release_manifest(directory, base_url)
    if version not in releases:
        raise ValueError(f"Release is not present: {version}")
    installer = (ROOT / "scripts/install.sh").read_text(encoding="utf-8")
    installer = re.sub(r'^DEFAULT_DOWNLOAD_URL="[^"]*"$',
                       f'DEFAULT_DOWNLOAD_URL="{base_url}"', installer, flags=re.MULTILINE)
    service_source = ROOT / "systemd/xboard-snell.service"
    with tempfile.TemporaryDirectory() as temporary:
        staging = Path(temporary) / "public"
        staging.mkdir()
        (staging / "install.sh").write_text(installer, encoding="utf-8")
        for tag, (manifest, files) in releases.items():
            release_path = f"xboard-snell/releases/{tag}"
            directory = staging / release_path
            directory.mkdir(parents=True)
            for source, name, _ in files:
                shutil.copy2(source, directory / name)
            shutil.copy2(service_source, directory / "xboard-snell.service")
            shutil.copy2(staging / "install.sh", directory / "install.sh")
            manifest["installer"] = asset_info(directory / "install.sh", f"{base_url}/{release_path}/install.sh")
            manifest["service"] = asset_info(directory / "xboard-snell.service", f"{base_url}/{release_path}/xboard-snell.service")
            sums = [f'{info["sha256"]}  {name}\n' for _, name, info in files]
            sums.append(f'{manifest["service"]["sha256"]}  xboard-snell.service\n')
            sums.append(f'{manifest["installer"]["sha256"]}  install.sh\n')
            (directory / "SHA256SUMS").write_text("".join(sums), encoding="utf-8")
            (directory / "version.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        current = dict(releases[version][0])
        current["stable"] = dict(current)
        current["versions"] = [{"tag": tag, "version": tag.removeprefix("v"),
                                "url": f"{base_url}/xboard-snell/releases/{tag}/version.json"}
                               for tag in reversed(releases)]
        (staging / "version.json").write_text(json.dumps(current, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        (staging / "latest.txt").write_text(version + "\n", encoding="utf-8")
        for name in ("index.html", "style.css", "site.js", "_headers", "404.html"):
            shutil.copy2(ROOT / "web" / name, staging / name)
        output.parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(staging, output)
    return current


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--assets", type=Path, help="Directory containing one subdirectory per release")
    source.add_argument("--repository", help="Private GitHub repository; downloads use gh's existing authentication")
    parser.add_argument("--version", default="latest", help="Published stable release tag or latest")
    parser.add_argument("--keep", type=int, default=5, choices=range(1, 11), help="Number of stable releases to retain")
    parser.add_argument("--base-url", default="https://assets.nowhere.best")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        with tempfile.TemporaryDirectory() as temporary:
            assets = args.assets
            version = args.version
            if args.repository:
                assets = Path(temporary) / "releases"
                version = download_releases(args.repository, version, assets, args.keep)
            result = build_site(assets, version, args.base_url, args.output)
        print(f'Built public download site: {args.output} (stable {result["version"]})')
    except (ValueError, OSError, subprocess.SubprocessError, KeyError) as error:
        parser.exit(1, f"Download site build failed: {error}\n")


if __name__ == "__main__":
    main()
