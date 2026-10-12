import contextlib
import io
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from PacketReader.Scripts import Capture as app
from scripts import build_release, make_demo


class ReleaseTests(unittest.TestCase):
    def test_source_allowlist(self):
        hashes = build_release.check_release()
        self.assertEqual(len(hashes), len(build_release.FILES))
        self.assertTrue(all(len(value) == 64 for value in hashes.values()))
        self.assertFalse(any(".private-captures" in name or ".venv" in name for name in hashes))

    def test_archive_excludes_private_decoy_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in build_release.FILES:
                target = root / name
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(build_release.ROOT / name, target)
            (root / "secret.pcap").write_bytes(b"synthetic-private-decoy")
            with zipfile.ZipFile(build_release.build_release(root)) as archive:
                self.assertEqual(
                    set(archive.namelist()), set(build_release.FILES) | {"RELEASE-MANIFEST.json"}
                )
                self.assertNotIn("secret.pcap", archive.namelist())

    def test_personal_whitelist_blocks_packaging(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in build_release.FILES:
                target = root / name
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(build_release.ROOT / name, target)
            (root / "PacketReader/Scripts/Data/Whitelist.json").write_text(
                json.dumps({"Whitelist": ["192.0.2.1"]}), encoding="utf-8"
            )
            with self.assertRaises(ValueError):
                build_release.check_release(root)

    def test_demo_is_offline_and_has_expected_indicators(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with (
                patch("scapy.sendrecv.sniff", side_effect=AssertionError("capture forbidden")),
                patch.object(
                    app.psutil, "net_connections", side_effect=AssertionError("socket lookup forbidden")
                ),
            ):
                pcap = make_demo.make_demo(root / "demo/demo.pcap")
                with contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(
                        app.main(
                            [
                                "--read",
                                str(pcap),
                                "--output-dir",
                                str(root / "out"),
                                "--syn-threshold",
                                "3",
                                "--udp-threshold",
                                "3",
                            ]
                        ),
                        0,
                    )
            summary = json.loads(next((root / "out").glob("*/summary.json")).read_text())
            self.assertEqual(summary["packets_seen"], 10)
            self.assertEqual(
                summary["indicator_counts"],
                {"syn_burst": 1, "udp_burst": 1, "payload_keyword": 1, "long_dns_txt": 1},
            )
            with self.assertRaises(FileExistsError):
                make_demo.make_demo(pcap)


if __name__ == "__main__":
    unittest.main()
