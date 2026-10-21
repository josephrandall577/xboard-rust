#!/usr/bin/env python3
"""Exercise the installer in a temporary layout with fake OS/network commands."""

import hashlib
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import tomllib
import unittest

ROOT = Path(__file__).resolve().parent.parent

# OS/network boundaries only. Installation writes are restricted to a temp dir.
FAKE_COMMAND = r'''#!/usr/bin/env python3
import hashlib, os, pathlib, shutil, sys
name = pathlib.Path(sys.argv[0]).name
args = sys.argv[1:]
root = pathlib.Path(os.environ["INSTALL_TEST_ROOT"])
if name == "uname":
    print("Linux" if args == ["-s"] else os.environ.get("INSTALL_TEST_ARCH", "x86_64"))
elif name == "id":
    print("0")
elif name == "getent":
    print("xboard-snell:x:999:999::/var/lib/xboard-snell:/usr/sbin/nologin")
elif name == "curl":
    with (root / "downloads.log").open("a") as log:
        log.write(args[-1] + "\n")
    source = root / "assets" / args[-1].rsplit("/", 1)[-1]
    shutil.copyfile(source, args[args.index("--output") + 1])
elif name == "sha256sum":
    expected, filename = sys.stdin.read().split()
    sys.exit(0 if hashlib.sha256(pathlib.Path(filename).read_bytes()).hexdigest() == expected else 1)
elif name == "install":
    directories = False
    mode = 0o755
    paths = []
    while args:
        arg = args.pop(0)
        if arg == "-d":
            directories = True
        elif arg in ("-o", "-g"):
            args.pop(0)
        elif arg == "-m":
            mode = int(args.pop(0), 8)
        else:
            paths.append(pathlib.Path(arg))
    for path in paths if directories else paths[-1:]:
        assert path.is_relative_to(root), path
        if directories:
            path.mkdir(parents=True, exist_ok=True)
        else:
            shutil.copyfile(paths[0], path)
        path.chmod(mode)
elif name == "systemctl":
    with (root / "systemctl.log").open("a") as log:
        log.write(" ".join(args) + "\n")
    if args[:1] == ["is-active"] and os.environ.get("INSTALL_TEST_SERVICE_FAIL"):
        sys.exit(1)
elif name in ("sleep", "useradd"):
    pass
else:
    raise RuntimeError(name)
'''


class InstallerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.assets = self.root / "assets"
        self.assets.mkdir()
        self.bin = self.root / "commands"
        self.bin.mkdir()
        for name in ("uname", "id", "getent", "curl", "sha256sum", "install", "systemctl", "sleep", "useradd"):
            path = self.bin / name
            path.write_text(FAKE_COMMAND)
            path.chmod(0o755)
        self.config = self.root / "etc/config.toml"
        self.installed = self.root / "bin/xboard-snell"
        self.state = self.root / "state"
        self.env = dict(os.environ, PATH=str(self.bin) + os.pathsep + os.environ["PATH"],
                        INSTALL_TEST_ROOT=str(self.root), TMPDIR=str(self.root),
                        PANEL_URL="https://panel.example.com", PANEL_TOKEN='test-"token\\value',
                        NODE_ID="7", SNELL_PSK="installer-test-psk-0123456789",
                        XBOARD_SNELL_VERSION="latest", XBOARD_SNELL_DOWNLOAD_URL="https://assets.nowhere.best")
        (self.assets / "latest.txt").write_text("v-test\n")
        self.make_archive()

    def make_archive(self, target="x86_64-unknown-linux-musl"):
        name = f"xboard-snell-v-test-{target}"
        archive = self.assets / f"{name}.tar.gz"
        binary = ROOT / "target/debug/xboard-snell"
        if not binary.is_file():
            self.fail("Build the node first: cargo build --locked")
        with tarfile.open(archive, "w:gz") as package:
            package.add(binary, arcname=f"{name}/xboard-snell")
            package.add(ROOT / "systemd/xboard-snell.service", arcname=f"{name}/systemd/xboard-snell.service")
        checksum = hashlib.sha256(archive.read_bytes()).hexdigest()
        service = self.assets / "xboard-snell.service"
        service.write_bytes((ROOT / "systemd/xboard-snell.service").read_bytes())
        service_hash = hashlib.sha256(service.read_bytes()).hexdigest()
        (self.assets / "SHA256SUMS").write_text(f"{checksum}  {archive.name}\n{service_hash}  xboard-snell.service\n")

    def run_installer(self, *args):
        # Redirect installation paths before invoking the production entry point.
        command = r'''
source "$1"
CONFIG_FILE="$INSTALL_TEST_ROOT/etc/config.toml"
BINARY_FILE="$INSTALL_TEST_ROOT/bin/xboard-snell"
SERVICE_FILE="$INSTALL_TEST_ROOT/units/xboard-snell.service"
STATE_DIR="$INSTALL_TEST_ROOT/state"
shift
main "$@"
'''
        return subprocess.run(["bash", "-c", command, "installer-test", str(ROOT / "scripts/install.sh"), *args],
                              env=self.env, text=True, capture_output=True, timeout=30)

    def test_install_generates_valid_config_and_enables_service(self):
        result = self.run_installer()
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        config = tomllib.loads(self.config.read_text())
        self.assertEqual(self.env["PANEL_TOKEN"], config["panel"]["token"])
        self.assertEqual(7, config["panel"]["node_id"])
        self.assertTrue(config["admin"]["disabled"])
        self.assertEqual(0o640, self.config.stat().st_mode & 0o777)
        self.assertTrue(self.installed.is_file())
        calls = (self.root / "systemctl.log").read_text()
        self.assertIn("enable xboard-snell.service", calls)
        self.assertIn("restart xboard-snell.service", calls)
        self.assertNotIn(self.env["PANEL_TOKEN"], result.stdout + result.stderr)

    def test_upgrade_preserves_config_and_database(self):
        self.assertEqual(0, self.run_installer().returncode)
        original = self.config.read_bytes()
        database = self.state / "xboard-snell.db"
        database.write_bytes(b"existing database")
        self.env["PANEL_TOKEN"] = "replacement-must-not-be-written"
        result = self.run_installer()
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertEqual(original, self.config.read_bytes())
        self.assertEqual(b"existing database", database.read_bytes())

    def test_checksum_failure_does_not_modify_installation(self):
        (self.assets / "SHA256SUMS").write_text("0" * 64 + "  xboard-snell-v-test-x86_64-unknown-linux-musl.tar.gz\n")
        result = self.run_installer()
        self.assertNotEqual(0, result.returncode)
        self.assertIn("checksum verification failed", result.stderr)
        self.assertFalse(self.installed.exists())
        self.assertFalse(self.config.exists())
        self.assertNotIn("restart", (self.root / "systemctl.log").read_text())

    def test_arm64_release_is_selected(self):
        self.env["INSTALL_TEST_ARCH"] = "aarch64"
        self.make_archive("aarch64-unknown-linux-musl")
        result = self.run_installer()
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertIn("aarch64-unknown-linux-musl", result.stdout)

    def test_invalid_config_does_not_replace_existing_binary(self):
        self.config.parent.mkdir()
        self.config.write_text('[node]\npsk = "installer-test-psk-0123456789"\n')
        self.installed.parent.mkdir()
        self.installed.write_bytes(b"old binary")
        result = self.run_installer()
        self.assertNotEqual(0, result.returncode)
        self.assertEqual(b"old binary", self.installed.read_bytes())
        self.assertNotIn("restart", (self.root / "systemctl.log").read_text())

    def test_first_install_accepts_multi_node_config(self):
        source = self.root / "multi.toml"
        source.write_bytes((ROOT / "config.multi-node.example.toml").read_bytes())
        result = self.run_installer("--config", str(source), "--version", "v-test")
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertEqual(source.read_bytes(), self.config.read_bytes())

    def test_generated_psk_and_legacy_panel_api(self):
        self.env["SNELL_PSK"] = ""
        result = self.run_installer("--api-version", "1")
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        config = tomllib.loads(self.config.read_text())
        self.assertRegex(config["node"]["psk"], r"^[a-f0-9]{64}$")
        self.assertEqual(1, config["panel"]["api_version"])

    def test_public_site_download_needs_no_github_credentials(self):
        result = self.run_installer("--download-url", "https://downloads.example.com")
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        downloads = (self.root / "downloads.log").read_text().splitlines()
        self.assertTrue(all(url.startswith("https://downloads.example.com/") for url in downloads))
        self.assertIn("https://downloads.example.com/latest.txt", downloads)
        self.assertFalse(any("github.com" in url for url in downloads))

    def test_invalid_latest_version_is_rejected_before_downloading_binaries(self):
        (self.assets / "latest.txt").write_text("../../other-release\n")
        result = self.run_installer()
        self.assertNotEqual(0, result.returncode)
        self.assertFalse(self.installed.exists())
        self.assertNotIn(".tar.gz", (self.root / "downloads.log").read_text())

    def test_service_checksum_mismatch_prevents_install(self):
        (self.assets / "xboard-snell.service").write_text("unverified unit")
        result = self.run_installer()
        self.assertNotEqual(0, result.returncode)
        self.assertIn("checksum verification failed", result.stderr)
        self.assertFalse(self.installed.exists())

    def test_failed_service_is_reported(self):
        self.env["INSTALL_TEST_SERVICE_FAIL"] = "1"
        result = self.run_installer()
        self.assertNotEqual(0, result.returncode)
        self.assertIn("journalctl", result.stderr)


if __name__ == "__main__":
    unittest.main()
