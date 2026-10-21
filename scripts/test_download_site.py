#!/usr/bin/env python3
"""Public site behavior, manifest integrity and publication boundaries."""

import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent.parent
TARGETS = [
    "x86_64-unknown-linux-musl", "aarch64-unknown-linux-musl",
    "x86_64-apple-darwin", "aarch64-apple-darwin",
    "x86_64-pc-windows-msvc", "aarch64-pc-windows-msvc",
]


class DownloadSiteTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.assets = self.root / "assets"
        self.output = self.root / "public"
        self.create_release("v1.2.0")
        self.create_release("v1.1.1")

    def create_release(self, tag):
        directory = self.assets / tag
        directory.mkdir(parents=True)
        sums = []
        for target in TARGETS:
            extension = "zip" if "windows" in target else "tar.gz"
            name = f"xboard-snell-{tag}-{target}.{extension}"
            payload = f"binary fixture for {target} {tag}".encode()
            (directory / name).write_bytes(payload)
            sums.append(f"{hashlib.sha256(payload).hexdigest()}  {name}\n")
        (directory / "SHA256SUMS").write_text("".join(sums))
        (directory / "release.json").write_text(json.dumps({"tagName": tag, "body": f"Release {tag}\n修复连接问题。", "isPrerelease": False, "isDraft": False}))
        (directory / "private-source.rs").write_text("PRIVATE_SOURCE_MUST_NOT_BE_PUBLISHED")

    def build(self, *extra):
        return subprocess.run([
            "python3", str(ROOT / "scripts/build_download_site.py"),
            "--assets", str(self.assets), "--version", "v1.2.0",
            "--base-url", "https://assets.nowhere.best", "--output", str(self.output), *extra,
        ], text=True, capture_output=True, timeout=30)

    def test_site_contains_real_platform_metadata_and_only_public_assets(self):
        result = self.build()
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        manifest = json.loads((self.output / "version.json").read_text())
        self.assertEqual(1, manifest["schemaVersion"])
        self.assertEqual("1.2.0", manifest["version"])
        self.assertEqual("1.2.0", manifest["stable"]["version"])
        self.assertIn("修复连接问题", manifest["notes"])
        self.assertEqual("v1.2.0\n", (self.output / "latest.txt").read_text())
        for platform in ("linux", "macos", "win"):
            for architecture in ("x64", "arm64"):
                asset = manifest[platform][architecture]
                relative = asset["url"].removeprefix("https://assets.nowhere.best/")
                payload = (self.output / relative).read_bytes()
                self.assertEqual(hashlib.sha256(payload).hexdigest(), asset["sha256"])
                self.assertEqual(len(payload), asset["size"])
        self.assertEqual(manifest["linux"]["x64"]["url"], manifest["url"])
        self.assertTrue((self.output / "xboard-snell/releases/v1.1.1/version.json").is_file())
        installer = (self.output / "install.sh").read_text()
        self.assertIn('DEFAULT_DOWNLOAD_URL="https://assets.nowhere.best"', installer)
        self.assertNotIn("github.com/$REPO", installer)
        self.assertFalse(list(self.output.rglob("*.rs")))
        self.assertFalse(list(self.output.rglob("release.json")))
        self.assertTrue((self.output / "404.html").is_file())
        self.assertIn("no-store", (self.output / "_headers").read_text())

    def test_checksum_mismatch_prevents_publication(self):
        path = next((self.assets / "v1.2.0").glob("*.zip"))
        path.write_bytes(b"tampered release")
        result = self.build()
        self.assertNotEqual(0, result.returncode)
        self.assertIn("checksum", result.stderr.lower())
        self.assertFalse(self.output.exists())

    def test_missing_platform_prevents_incomplete_release(self):
        next((self.assets / "v1.2.0").glob("*.zip")).unlink()
        result = self.build()
        self.assertNotEqual(0, result.returncode)
        self.assertFalse(self.output.exists())

    def test_symlinks_cannot_publish_files_outside_release(self):
        path = next((self.assets / "v1.2.0").glob("*.zip"))
        external = self.root / "external.zip"
        external.write_bytes(path.read_bytes())
        path.unlink()
        path.symlink_to(external)
        result = self.build()
        self.assertNotEqual(0, result.returncode)
        self.assertFalse(self.output.exists())

    def test_pages_file_size_limit_is_checked(self):
        path = next((self.assets / "v1.2.0").glob("*.zip"))
        with path.open("wb") as asset:
            asset.truncate(25 * 1024 * 1024 + 1)
        result = self.build()
        self.assertNotEqual(0, result.returncode)
        self.assertIn("25 MiB", result.stderr)
        self.assertFalse(self.output.exists())

    def test_invalid_base_url_is_rejected(self):
        result = self.build("--base-url", "https://user:password@assets.nowhere.best")
        self.assertNotEqual(0, result.returncode)
        self.assertFalse(self.output.exists())


if __name__ == "__main__":
    unittest.main()
