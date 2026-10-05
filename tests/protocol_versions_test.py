import importlib.util
import io
import json
import re
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("pins", ROOT / "scripts/update_protocol_versions.py")
pins = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pins)


class VersionPinsTests(unittest.TestCase):
    def test_image_defaults_match_checked_in_pins(self):
        keys = r'(?:SINGBOX|MIHOMO|MIERU)_(?:VERSION|SHA256|SOURCE_SHA256)'
        values = dict(re.findall(r'^(' + keys + r')=(.+)$', (ROOT / '.env').read_text(), re.M))
        for name in ('php', 'protocol', 'mieru'):
            defaults = re.findall(r'^ARG (' + keys + r')=(.+)$', (ROOT / f'dockerfile/{name}.dockerfile').read_text(), re.M)
            self.assertTrue(defaults)
            for key, value in defaults:
                self.assertEqual(values[key], value, f'{name}: {key}')
        defaults = re.findall(r'\$\{(' + keys + r'):-([^}]+)\}', (ROOT / 'docker-compose.yml').read_text())
        self.assertTrue(defaults)
        for key, value in defaults:
            self.assertEqual(values[key], value, f'Compose: {key}')

    def test_version_rejects_non_stable_or_command_input(self):
        for value in ("", "1.2", "v1.2.3-beta1", "../tags/v1.2.3", "1.2.3\n", "$(id)", "1.2.3;id"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                pins.version(value)
        self.assertEqual("v1.14.1", pins.version("1.14.1"))
        self.assertEqual("latest", pins.version("latest"))

    def test_only_requested_lines_change_and_mode_is_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / ".env"
            before = "# keep\nCUSTOM='test fixture value'\nSINGBOX_VERSION=v1.14.0\n"
            path.write_text(before); path.chmod(0o600)
            values = {"SINGBOX_VERSION": "v1.14.1", "SINGBOX_SHA256": "a" * 64}
            pins.update_file(path, values, True)
            self.assertEqual(before, path.read_text())
            pins.update_file(path, values)
            self.assertEqual(before.replace("v1.14.0", "v1.14.1") + "SINGBOX_SHA256=" + "a" * 64 + "\n", path.read_text())
            self.assertEqual(0o600, path.stat().st_mode & 0o777)
            data = path.read_bytes(); pins.update_file(path, values)
            self.assertEqual(data, path.read_bytes())
            self.assertFalse(list(path.parent.glob(".version-pins-*")))

    def test_duplicates_symlinks_and_racing_edits_fail_closed(self):
        with self.assertRaises(ValueError):
            pins.updated_text("SINGBOX_VERSION=v1.1.1\nexport SINGBOX_VERSION=v1.2.2\n", {"SINGBOX_VERSION": "v1.14.1"})
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / ".env"; path.write_text("SINGBOX_VERSION=v1.1.1\n")
            link = Path(directory) / "link"; link.symlink_to(path)
            with self.assertRaises(ValueError): pins.update_file(link, {"SINGBOX_VERSION": "v1.14.1"})
            real_fsync = pins.os.fsync
            def change(fd):
                real_fsync(fd)
                path.write_text("CUSTOM=concurrent-change\n")
            with patch.object(pins.os, "fsync", side_effect=change), self.assertRaises(ValueError):
                pins.update_file(path, {"SINGBOX_VERSION": "v1.14.1"})
            self.assertEqual("CUSTOM=concurrent-change\n", path.read_text())
            self.assertFalse(list(path.parent.glob(".version-pins-*")))

    def test_release_uses_verified_official_asset_and_source(self):
        release = {"tag_name": "v1.14.1", "prerelease": False, "draft": False, "assets": [
            {"name": "sing-box-1.14.1-linux-amd64-musl.tar.gz", "digest": "sha256:" + "a" * 64}]}
        requests = []
        def metadata(url):
            requests.append(url)
            return io.BytesIO(json.dumps(release).encode())
        with patch.object(pins, "request", side_effect=metadata), patch.object(pins, "digest", return_value="a" * 64) as digest:
            result = pins.release_pins("singbox", "latest")
            self.assertEqual("v1.14.1", result["SINGBOX_VERSION"])
            self.assertEqual("a" * 64, result["SINGBOX_SOURCE_SHA256"])
            self.assertEqual(["https://api.github.com/repos/SagerNet/sing-box/releases/latest"], requests)
            self.assertTrue(all(call.args[0].startswith(("https://codeload.github.com/SagerNet/sing-box/", "https://github.com/SagerNet/sing-box/")) for call in digest.call_args_list))
        with patch.object(pins, "request", side_effect=metadata), patch.object(pins, "digest", return_value="b" * 64), self.assertRaises(ValueError):
            pins.release_pins("singbox", "v1.14.1")
        release["prerelease"] = True
        with patch.object(pins, "request", side_effect=metadata), self.assertRaises(ValueError):
            pins.release_pins("singbox", "latest")

    def test_compose_passes_pins_to_every_affected_image(self):
        text = (ROOT / "docker-compose.yml").read_text()
        for service in ("anytls", "tuic", "shadowtls"):
            block = text.split("    " + service + ":\n", 1)[1]
            block = block.split("        environment:", 1)[0]
            self.assertIn("SINGBOX_VERSION:", block)
            self.assertIn("SINGBOX_SOURCE_SHA256:", block)
            self.assertIn("PROTOCOL_GO_VERSION:", block)
        self.assertEqual(2, text.count("                MIHOMO_SHA256:"))
        ci = (ROOT / ".github/workflows/images.yml").read_text()
        # A release is now a complete set: every pin change builds and tests all
        # shared images, so there is no partial env-to-target filter to maintain.
        for service in ('php', 'anytls', 'mieru'):
            self.assertIn('{service: ' + service + ', image:', ci)
        self.assertIn('files: docker-compose.yml', ci)


if __name__ == "__main__":
    unittest.main()
