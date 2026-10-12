"""Offline regression tests. No capture sockets or real traffic."""

import base64
import contextlib
import ctypes
from ctypes import wintypes
import io
import json
import os
from pathlib import Path
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from PacketReader.Scripts import Capture as app
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6, IPv6ExtHdrFragment, IPv6ExtHdrHopByHop
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Raw
from scapy.utils import PcapWriter


def packet(layer=None, timestamp=100):
    result = Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02") / (
        layer if layer is not None else IP(src="192.0.2.1", dst="198.51.100.1") / TCP()
    )
    result.time = timestamp
    return result


def write_pcap(path, packets):
    with PcapWriter(str(path), linktype=1, sync=True) as writer:
        writer.write_header(None)
        for item in packets:
            writer.write(item)


class ConfigTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.config = Path(self.temp.name) / "config"
        shutil.copytree(app.DATA_DIRECTORY, self.config)

    def change(self, name, value):
        (self.config / name).write_text(json.dumps(value), encoding="utf-8")

    def test_services_are_cached_and_independent_of_working_directory(self):
        before = {p.name: p.read_bytes() for p in self.config.iterdir()}
        old = Path.cwd()
        try:
            os.chdir(self.temp.name)
            assessment = app.PacketAssessment(self.config)
            with patch.object(Path, "open", side_effect=AssertionError("configuration reopened")):
                self.assertEqual(assessment.port_hint(443), "HTTPs")
                self.assertEqual(assessment.port_hint(53), "DNS")
                self.assertIsNone(assessment.port_hint(10001))
        finally:
            os.chdir(old)
        self.assertEqual(before, {p.name: p.read_bytes() for p in self.config.iterdir()})

    def test_keyword_schema(self):
        self.assertIn("password", app.PacketAssessment(self.config).keywords)
        self.assertNotIn("Keywords", app.PacketAssessment(self.config).keywords)

    def test_missing_configuration_never_recreates_it(self):
        target = self.config / "Services.json"
        target.unlink()
        with self.assertRaises(ValueError):
            app.PacketAssessment(self.config)
        self.assertFalse(target.exists())

    def test_malformed_json(self):
        (self.config / "Whitelist.json").write_text("{", encoding="utf-8")
        with self.assertRaises(ValueError):
            app.PacketAssessment(self.config)

    def test_invalid_shapes(self):
        cases = [
            ("Whitelist.json", {"Whitelist": [""]}),
            ("Whitelist.json", {"Whitelist": "192.0.2.1"}),
            ("SuspisciousKeywords.json", {"Keywords": [""]}),
            ("SuspisciousKeywords.json", {"Keywords": "password"}),
            ("Services.json", {"Services": {"65536": "x"}, "Range": []}),
            ("Services.json", {"Services": {}, "Range": [{"start": True, "end": 5, "name": "x"}]}),
            ("Services.json", {"Services": {}, "Range": [{"start": 5, "end": 2, "name": "x"}]}),
            ("Services.json", []),
        ]
        for name, value in cases:
            with self.subTest(name=name, value=value):
                original = (self.config / name).read_bytes()
                self.change(name, value)
                with self.assertRaises(ValueError):
                    app.PacketAssessment(self.config)
                (self.config / name).write_bytes(original)

    def test_whitelist_suppresses_indicators_but_keeps_metadata(self):
        self.change("Whitelist.json", {"Whitelist": ["192.0.2.1"]})
        assessment = app.PacketAssessment(self.config, syn_threshold=1)
        row, alerts = assessment.analyze(
            packet(IP(src="192.0.2.1", dst="198.51.100.1") / TCP(flags="S") / Raw(b"password"))
        )
        self.assertTrue(row["whitelisted"])
        self.assertEqual(alerts, [])
        self.assertEqual(assessment.summary()["packets_seen"], 1)


class PacketTests(unittest.TestCase):
    def test_actual_tcp_values_and_binary_payload_opt_in(self):
        item = packet(
            IP(src="192.0.2.1", dst="198.51.100.1") / TCP(seq=10, ack=50, flags="PA") / Raw(b"\xff\x00test")
        )
        assessment = app.PacketAssessment(include_payload=True)
        row, _ = assessment.analyze(item)
        self.assertEqual(row["acknowledgment"], 50)
        self.assertEqual(row["sequence"], 10)
        self.assertEqual(base64.b64decode(row["payload_base64"]), b"\xff\x00test")
        self.assertEqual(row["timestamp"], 100)
        row, _ = app.PacketAssessment().analyze(item)
        self.assertNotIn("payload_base64", row)

    def test_protocols_and_ipv6_lengths(self):
        assessment = app.PacketAssessment()
        layers = [
            IP() / TCP(),
            IP() / UDP() / Raw(b"x" * 1500),
            IPv6() / TCP(flags="FA"),
            IPv6() / UDP(),
            ARP(hwsrc="02:00:00:00:00:01", hwdst="02:00:00:00:00:02", psrc="192.0.2.1", pdst="198.51.100.1"),
            IP() / ICMP(),
            IPv6() / IPv6ExtHdrFragment(offset=1) / Raw(b"abc"),
            IPv6() / IPv6ExtHdrHopByHop() / UDP(),
            Raw(b"unknown"),
        ]
        for layer in layers:
            with self.subTest(layer=layer.summary()):
                item = packet(layer)
                row, _ = assessment.analyze(item)
                if IPv6 in item:
                    self.assertEqual(row["ip_header_length"], 40)
                    self.assertEqual(row["ip_total_length"], len(item[IPv6]))
                if ARP in item:
                    self.assertEqual(row["source"], "192.0.2.1")
                    self.assertEqual(row["destination"], "198.51.100.1")
        self.assertEqual(assessment.total, len(layers))

    def test_outer_ipv6_not_inner_ipv4(self):
        row, _ = app.PacketAssessment().analyze(
            packet(IPv6(src="2001:db8::1", dst="2001:db8::2") / IP() / TCP())
        )
        self.assertEqual(row["ip_version"], 6)
        self.assertEqual(row["source"], "2001:db8::1")
        self.assertNotEqual(row["protocol"], "TCP")

    def test_fin_rst_and_large_udp_are_not_attack_claims(self):
        assessment = app.PacketAssessment()
        for layer in [
            IP() / TCP(flags="FA", seq=1, ack=2),
            IP() / TCP(flags="RA", window=0),
            IP() / UDP() / Raw(b"x" * 1500),
        ]:
            self.assertEqual(assessment.analyze(packet(layer))[1], [])

    def test_keyword_uses_payload_not_packet_summary(self):
        row, alerts = app.PacketAssessment().analyze(packet(IP() / UDP() / Raw(b"PASSWORD=synthetic")))
        self.assertEqual(alerts[0]["rule"], "payload_keyword")
        self.assertNotIn("synthetic", json.dumps(alerts))
        self.assertNotIn("payload_base64", row)

    def test_keyword_scan_is_bounded(self):
        with patch.object(app, "MAX_SCAN_BYTES", 16):
            _, alerts = app.PacketAssessment().analyze(packet(IP() / TCP() / Raw(b"x" * 16 + b"password")))
        self.assertEqual(alerts, [])

    def test_dns_txt_udp_and_ipv6(self):
        for net in [IP(), IPv6()]:
            with self.subTest(version=net.version):
                dns = DNS(
                    qr=1,
                    qd=DNSQR(qname="example.test"),
                    an=DNSRR(rrname="example.test", type=16, rdata=[b"x" * 201]),
                )
                _, alerts = app.PacketAssessment().analyze(packet(net / UDP(sport=53) / dns))
                self.assertIn("long_dns_txt", [a["rule"] for a in alerts])
                _, alerts = app.PacketAssessment().analyze(
                    packet(net / UDP(sport=53) / DNS(qr=1, an=DNSRR(type=16, rdata=[b"short"])))
                )
                self.assertNotIn("long_dns_txt", [a["rule"] for a in alerts])

    def test_dns_multiple_records_and_tcp(self):
        dns = DNS(qr=1, an=[DNSRR(type=1, rdata="192.0.2.2"), DNSRR(type=16, rdata=[b"x" * 201])])
        _, alerts = app.PacketAssessment().analyze(packet(IP() / TCP(sport=53) / dns))
        self.assertIn("long_dns_txt", [a["rule"] for a in alerts])

    def test_burst_rules_and_syn_ack_exclusion(self):
        assessment = app.PacketAssessment(syn_threshold=3, udp_threshold=3)
        for timestamp in [1, 2]:
            self.assertEqual(assessment.analyze(packet(IP() / TCP(flags="S"), timestamp))[1], [])
        self.assertEqual(assessment.analyze(packet(IP() / TCP(flags="S"), 3))[1][0]["rule"], "syn_burst")
        self.assertEqual(assessment.analyze(packet(IP() / TCP(flags="S"), 4))[1], [])
        self.assertEqual(app.PacketAssessment(syn_threshold=1).analyze(packet(IP() / TCP(flags="SA")))[1], [])
        for timestamp in [1, 2, 3]:
            _, alerts = assessment.analyze(packet(IP() / UDP(), timestamp))
        self.assertEqual(alerts[0]["rule"], "udp_burst")

    def test_summary_addresses_and_flows(self):
        assessment = app.PacketAssessment()
        for port in [80, 443]:
            assessment.analyze(packet(IP(src="192.0.2.1", dst="198.51.100.1") / TCP(dport=port)))
        result = assessment.summary()
        self.assertEqual(result["unique_addresses"], 2)
        self.assertEqual(result["unique_flows"], 2)
        self.assertEqual(result["source_addresses"], ["192.0.2.1"])

    def test_summary_state_bound_is_reported(self):
        assessment = app.PacketAssessment()
        with patch.object(app, "MAX_IDENTITIES", 1):
            assessment.analyze(packet(IP(src="192.0.2.1", dst="198.51.100.1") / TCP()))
            assessment.analyze(packet(IP(src="192.0.2.2", dst="198.51.100.2") / TCP()))
        self.assertTrue(assessment.summary()["identity_counts_are_lower_bounds"])
        self.assertEqual(len(assessment.sources), 1)

    def test_truncated_record_is_marked(self):
        item = packet()
        item.wirelen = len(item) + 10
        self.assertTrue(app.PacketAssessment().analyze(item)[0]["truncated"])

    def test_invalid_timestamp(self):
        item = packet(timestamp=float("nan"))
        with self.assertRaises(ValueError):
            app.PacketAssessment().analyze(item)


class BurstTests(unittest.TestCase):
    def test_expiration_boundary_and_cooldown(self):
        tracker = app.BurstTracker(2, 10)
        self.assertFalse(tracker.observe("a", 0))
        self.assertFalse(tracker.observe("a", 10))
        self.assertTrue(tracker.observe("a", 11))
        self.assertFalse(tracker.observe("a", 12))
        self.assertTrue(tracker.observe("a", 21))

    def test_state_bound_and_clock_reversal(self):
        tracker = app.BurstTracker(2, 10, max_keys=2)
        for key in ["a", "b", "c"]:
            tracker.observe(key, 10)
        self.assertEqual(len(tracker.states), 2)
        self.assertFalse(tracker.observe("c", 1))
        self.assertEqual(len(tracker.states), 1)


class ProcessTests(unittest.TestCase):
    def row(self):
        return app.PacketAssessment().analyze(
            packet(IP(src="192.0.2.1", dst="198.51.100.1") / TCP(sport=1000, dport=443))
        )[0]

    def conn(self, pid=123, ip="192.0.2.1", kind=socket.SOCK_STREAM):
        return SimpleNamespace(
            family=socket.AF_INET,
            type=kind,
            pid=pid,
            laddr=SimpleNamespace(ip=ip, port=1000),
            raddr=SimpleNamespace(ip="198.51.100.1", port=443),
        )

    def test_outbound_inbound_and_cache(self):
        with (
            patch.object(app.psutil, "net_connections", return_value=[self.conn()]) as sockets,
            patch.object(app.psutil, "Process", return_value=SimpleNamespace(name=lambda: "demo.exe")),
        ):
            resolver = app.ProcessResolver(clock=lambda: 0)
            row = self.row()
            self.assertEqual(resolver.resolve(row)["pid"], 123)
            row["source"], row["destination"] = row["destination"], row["source"]
            row["source_port"], row["destination_port"] = row["destination_port"], row["source_port"]
            self.assertEqual(resolver.resolve(row)["pid"], 123)
            self.assertEqual(sockets.call_count, 1)

    def test_missing_pid_and_wrong_transport(self):
        with (
            patch.object(
                app.psutil,
                "net_connections",
                return_value=[self.conn(pid=None), self.conn(kind=socket.SOCK_DGRAM)],
            ),
            patch.object(app.psutil, "Process") as process,
        ):
            self.assertIsNone(app.ProcessResolver().resolve(self.row()))
            process.assert_not_called()

    def test_ambiguous_processes_are_unknown(self):
        with patch.object(app.psutil, "net_connections", return_value=[self.conn(1), self.conn(2)]):
            self.assertIsNone(app.ProcessResolver().resolve(self.row()))

    def test_wildcard_with_remote_endpoint(self):
        with (
            patch.object(app.psutil, "net_connections", return_value=[self.conn(ip="0.0.0.0")]),
            patch.object(app.psutil, "Process", return_value=SimpleNamespace(name=lambda: "demo")),
        ):
            self.assertEqual(app.ProcessResolver().resolve(self.row())["pid"], 123)

    def test_wildcard_without_remote_endpoint_is_unknown(self):
        connection = self.conn(ip="0.0.0.0")
        connection.raddr = ()
        with patch.object(app.psutil, "net_connections", return_value=[connection]):
            self.assertIsNone(app.ProcessResolver().resolve(self.row()))

    def test_access_denial_and_process_exit(self):
        with patch.object(app.psutil, "net_connections", side_effect=app.psutil.AccessDenied):
            resolver = app.ProcessResolver()
            self.assertIsNone(resolver.resolve(self.row()))
            self.assertEqual(resolver.errors, 1)
        with (
            patch.object(app.psutil, "net_connections", return_value=[self.conn()]),
            patch.object(app.psutil, "Process", side_effect=app.psutil.NoSuchProcess(123)),
        ):
            self.assertIsNone(app.ProcessResolver().resolve(self.row()))


class OutputAndCLITests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.pcap = self.root / "synthetic.pcap"
        write_pcap(self.pcap, [packet(timestamp=x) for x in [1, 2, 3]])

    def run_main(self, extra=()):
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            return app.main(["--read", str(self.pcap), "--output-dir", str(self.root / "output"), *extra])

    def summary(self):
        return json.loads(next((self.root / "output").glob("*/summary.json")).read_text())

    def test_offline_pipeline_never_uses_capture_or_process_apis(self):
        with (
            patch("scapy.sendrecv.sniff", side_effect=AssertionError("live capture")),
            patch.object(app.psutil, "net_connections", side_effect=AssertionError("local sockets")),
        ):
            self.assertEqual(self.run_main(["--count", "2"]), 0)
        self.assertEqual(self.summary()["packets_seen"], 2)
        folder = next((self.root / "output").iterdir())
        self.assertFalse((folder / "capture.pcap").exists())
        self.assertNotIn("payload_base64", (folder / "packets.jsonl").read_text())

    def test_session_names_prevent_overwrite(self):
        self.assertEqual(self.run_main(), 0)
        first = next((self.root / "output").glob("*/packets.jsonl"))
        contents = first.read_bytes()
        self.assertEqual(self.run_main(), 0)
        self.assertEqual(len(list((self.root / "output").iterdir())), 2)
        self.assertEqual(first.read_bytes(), contents)

    def test_optional_raw_pcap_round_trip(self):
        self.assertEqual(self.run_main(["--save-pcap"]), 0)
        target = next((self.root / "output").glob("*/capture.pcap"))
        app.validate_pcap(target, 100)
        with app.PcapReader(str(target)) as reader:
            self.assertEqual(len(list(reader)), 3)

    def test_callback_error_preserves_previous_rows_and_reports_failure(self):
        original = app.PacketAssessment.analyze

        def analyze(assessment, item):
            if assessment.total == 1:
                raise ValueError("bad packet")
            return original(assessment, item)

        with patch.object(app.PacketAssessment, "analyze", analyze):
            self.assertEqual(self.run_main(), 1)
        self.assertEqual(self.summary()["status"], "failed")
        self.assertEqual(self.summary()["packet_errors"], 1)
        self.assertEqual(
            len(next((self.root / "output").glob("*/packets.jsonl")).read_text().splitlines()), 1
        )

    def test_keyboard_interrupt_finalizes(self):
        with patch.object(app.PacketAssessment, "analyze", side_effect=KeyboardInterrupt):
            self.assertEqual(self.run_main(), 130)
        self.assertEqual(self.summary()["status"], "interrupted")

    def test_output_failure_finalizes(self):
        with patch.object(app.SessionOutput, "write", side_effect=OSError("disk full")):
            self.assertEqual(self.run_main(), 1)
        self.assertEqual(self.summary()["status"], "failed")

    def test_finalization_failure_is_nonzero(self):
        with patch.object(app.os, "replace", side_effect=OSError("replace failed")):
            self.assertEqual(self.run_main(), 1)

    def test_constructor_permission_failure_is_nonzero(self):
        with patch.object(app, "secure_directory", side_effect=OSError("access denied")):
            self.assertEqual(self.run_main(), 1)

    def test_close_attempts_all_streams(self):
        output = app.SessionOutput(self.root / "out")
        output.rows.close()
        output.alerts.close()
        output.rows = Mock(close=Mock(side_effect=OSError("close failed")))
        output.alerts = Mock()
        with self.assertRaises(OSError):
            output.finish({"status": "completed"})
        output.alerts.close.assert_called_once()
        self.assertEqual(json.loads((output.directory / "summary.json").read_text())["status"], "failed")

    def test_bad_pcap_and_oversized_record_are_rejected(self):
        for contents in [
            b"bad",
            struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
            + struct.pack("<IIII", 0, 0, 1048577, 1048577),
            self.pcap.read_bytes()[:-1],
        ]:
            with self.subTest(size=len(contents)):
                self.pcap.write_bytes(contents)
                self.assertEqual(self.run_main(), 1)
        self.assertFalse((self.root / "output").exists())

    def test_empty_pcap(self):
        write_pcap(self.pcap, [])
        self.assertEqual(self.run_main(), 0)
        self.assertEqual(self.summary()["packets_seen"], 0)

    def test_read_allocation_guard(self):
        bounded = app.LimitedPcapFile(io.BytesIO(b"abc"))
        self.assertEqual(bounded.read(2), b"ab")
        for size in [-1, 1000000000]:
            with self.assertRaises(ValueError):
                bounded.read(size)

    def test_output_cannot_change_project_root_permissions(self):
        with self.assertRaises(OSError):
            app.secure_directory(app.DATA_DIRECTORY.parents[2])
        with self.assertRaises(OSError):
            app.secure_directory(app.DATA_DIRECTORY / ".." / ".." / "..")

    @unittest.skipUnless(os.name == "nt", "Windows mapped drive protection")
    def test_network_drive_is_rejected_before_writes(self):
        kernel = SimpleNamespace(GetDriveTypeW=Mock(return_value=4))
        with patch.object(app.ctypes, "WinDLL", return_value=kernel):
            with self.assertRaises(OSError):
                app.secure_directory(self.root / "network-output")
            with self.assertRaises(ValueError):
                app.validate_pcap(self.pcap, 1)
        self.assertFalse((self.root / "network-output").exists())

    def test_cli_validation(self):
        for args in [
            [],
            ["--duration", "nan"],
            ["--count", "0"],
            ["--syn-threshold", "10001"],
            ["--read", str(self.pcap), "--processes"],
            ["--read", str(self.pcap), "--iface", "x"],
        ]:
            with self.subTest(args=args), contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as caught:
                    app.main(args)
                self.assertEqual(caught.exception.code, 2)

    def test_live_callback_failure_stops_and_finalizes_without_capture(self):
        def fake_sniff(**kwargs):
            kwargs["prn"](packet())
            self.assertTrue(kwargs["stop_filter"](packet()))
            self.assertTrue(kwargs["chainCC"])

        with (
            patch("scapy.sendrecv.sniff", side_effect=fake_sniff),
            patch.object(app.PacketAssessment, "analyze", side_effect=ValueError),
            contextlib.redirect_stdout(io.StringIO()),
            contextlib.redirect_stderr(io.StringIO()),
        ):
            self.assertEqual(app.main(["--iface", "synthetic", "--output-dir", str(self.root / "output")]), 1)
        self.assertEqual(self.summary()["status"], "failed")

    def test_premature_live_stop_is_failure(self):
        with (
            patch("scapy.sendrecv.sniff"),
            contextlib.redirect_stdout(io.StringIO()),
            contextlib.redirect_stderr(io.StringIO()),
        ):
            self.assertEqual(app.main(["--iface", "synthetic", "--output-dir", str(self.root / "output")]), 1)

    def test_directory_acl_is_private(self):
        directory = app.secure_directory(self.root / "private")
        path = directory / "check.txt"
        path.write_text("synthetic", encoding="utf-8")
        if os.name == "nt":
            advapi = ctypes.WinDLL("advapi32", use_last_error=True)
            advapi.GetFileSecurityW.argtypes = [
                wintypes.LPCWSTR,
                wintypes.DWORD,
                ctypes.c_void_p,
                wintypes.DWORD,
                ctypes.POINTER(wintypes.DWORD),
            ]
            advapi.ConvertSecurityDescriptorToStringSecurityDescriptorW.argtypes = [
                ctypes.c_void_p,
                wintypes.DWORD,
                wintypes.DWORD,
                ctypes.POINTER(wintypes.LPWSTR),
                ctypes.c_void_p,
            ]
            required = wintypes.DWORD()
            advapi.GetFileSecurityW(str(path), 4, None, 0, ctypes.byref(required))
            buffer = ctypes.create_string_buffer(required.value)
            self.assertTrue(advapi.GetFileSecurityW(str(path), 4, buffer, required, ctypes.byref(required)))
            text = wintypes.LPWSTR()
            self.assertTrue(
                advapi.ConvertSecurityDescriptorToStringSecurityDescriptorW(
                    buffer, 1, 4, ctypes.byref(text), None
                )
            )
            try:
                sddl = text.value
                self.assertEqual(sddl.count("(A;"), 2)
                self.assertIn(";;;SY)", sddl)
                self.assertNotIn(";;;BU)", sddl)
                self.assertNotIn(";;;WD)", sddl)
                self.assertNotIn(";;;AU)", sddl)
            finally:
                kernel = ctypes.WinDLL("kernel32")
                kernel.LocalFree.argtypes = [ctypes.c_void_p]
                kernel.LocalFree(ctypes.cast(text, ctypes.c_void_p))
        else:
            self.assertEqual(directory.stat().st_mode & 0o777, 0o700)

    def test_both_launchers_work_from_another_directory(self):
        root = app.DATA_DIRECTORY.parents[2]
        for script in (root / "capture.py", root / "PacketReader/Scripts/Capture.py"):
            result = subprocess.run(
                [sys.executable, "-B", str(script), "--help"],
                cwd=self.root,
                capture_output=True,
                text=True,
                check=True,
            )
            self.assertIn("--read", result.stdout)


if __name__ == "__main__":
    unittest.main()
