"""Foocap: bounded passive packet inspection and offline PCAP analysis."""

from __future__ import annotations

import argparse
import base64
from collections import Counter, OrderedDict, deque
import ctypes
from ctypes import wintypes
from datetime import datetime, timezone
import ipaddress
import json
import math
import os
from pathlib import Path
import socket
import struct
import sys
import time
import uuid

import psutil
from scapy.config import conf

# Avoid route-table discovery during offline imports/analysis.
conf.route_autoload = False
conf.route6_autoload = False
from scapy.layers.dns import DNS  # noqa: E402
from scapy.layers.inet import IP, TCP, UDP  # noqa: E402
from scapy.layers.inet6 import IPv6  # noqa: E402
from scapy.layers.l2 import ARP, Ether  # noqa: E402
from scapy.packet import NoPayload  # noqa: E402
from scapy.utils import PcapReader, PcapWriter  # noqa: E402

DATA_DIRECTORY = Path(__file__).resolve().parent / "Data"
MAX_IDENTITIES = 10000
MAX_SCAN_BYTES = 65536
MAX_PACKET_BYTES = 65535


def load_config(directory=DATA_DIRECTORY):
    """Validate configuration without creating or changing files."""

    def read(name):
        path = Path(directory) / name
        try:
            with path.open(encoding="utf-8") as stream:
                result = json.load(stream)
        except (OSError, ValueError) as exc:
            raise ValueError(f"Cannot load configuration {path}: {exc}") from exc
        if not isinstance(result, dict):
            raise ValueError(f"{path.name} must contain a JSON object")
        return result

    whitelist = read("Whitelist.json").get("Whitelist")
    keywords = read("SuspisciousKeywords.json").get("Keywords")
    services = read("Services.json")
    if not isinstance(whitelist, list) or not all(isinstance(x, str) for x in whitelist):
        raise ValueError("Whitelist must be a list of IP address strings")
    try:
        whitelist = {str(ipaddress.ip_address(x)) for x in whitelist}
    except ValueError as exc:
        raise ValueError("Whitelist contains an invalid IP address") from exc
    if (
        not isinstance(keywords, list)
        or not all(isinstance(x, str) and 0 < len(x) <= 128 for x in keywords)
        or len(keywords) > 100
    ):
        raise ValueError("Keywords must contain at most 100 nonempty strings (max 128 characters)")
    ports, ranges = services.get("Services"), services.get("Range")
    if not isinstance(ports, dict) or not isinstance(ranges, list):
        raise ValueError("Services must contain a Services object and a Range list")
    try:
        for port, label in ports.items():
            if not port.isdecimal() or not 0 <= int(port) <= 65535:
                raise ValueError("invalid port")
            if not isinstance(label, str) or not label:
                raise ValueError("invalid service label")
        for item in ranges:
            if not isinstance(item, dict):
                raise ValueError("invalid range")
            start, end = item["start"], item["end"]
            if type(start) is not int or type(end) is not int or not 0 <= start <= end <= 65535:
                raise ValueError("invalid range endpoints")
            if not isinstance(item["name"], str) or not item["name"]:
                raise ValueError("invalid range label")
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError(f"Invalid service mapping: {exc}") from exc
    return whitelist, tuple(dict.fromkeys(keywords)), ports, ranges


def secure_directory(path):
    """Restrict a dedicated output directory before sensitive writes."""
    path = Path(path).absolute()
    for ancestor in (path, *path.parents):
        if ancestor.is_symlink() or getattr(ancestor, "is_junction", lambda: False)():
            raise OSError("Output paths must not contain links or junctions")
    path = path.resolve()
    if os.name == "nt" and str(path).startswith("\\\\"):
        raise OSError("Network output directories are not supported")
    if os.name == "nt":
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.GetDriveTypeW.argtypes = [wintypes.LPCWSTR]
        if kernel.GetDriveTypeW(path.anchor) == 4:
            raise OSError("Mapped network output directories are not supported")
    reserved = {
        Path.home().absolute(),
        Path.cwd().absolute(),
        DATA_DIRECTORY,
        DATA_DIRECTORY.parents[2],
        *Path.home().absolute().parents,
    }
    if os.environ.get("LOCALAPPDATA"):
        reserved.add(Path(os.environ["LOCALAPPDATA"]).absolute())
    if path in reserved:
        raise OSError("Choose a dedicated output folder, not a home, project, or system directory")
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    restrict_access(path)
    return path


def restrict_access(path):
    """Set a private DACL/mode on an owned file or directory."""
    path = Path(path)
    if os.name != "nt":
        path.chmod(0o700 if path.is_dir() else 0o600)
        return
    # Protected DACL: current token user and SYSTEM; inherited by files.
    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.GetCurrentProcess.restype = wintypes.HANDLE
    kernel.LocalFree.argtypes = [ctypes.c_void_p]
    kernel.LocalFree.restype = ctypes.c_void_p
    advapi.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
    advapi.GetTokenInformation.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    ]
    advapi.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.LPWSTR)]
    advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.c_void_p,
    ]
    advapi.SetFileSecurityW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, ctypes.c_void_p]
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    token, sid_text, descriptor = wintypes.HANDLE(), wintypes.LPWSTR(), ctypes.c_void_p()
    try:
        if not advapi.OpenProcessToken(kernel.GetCurrentProcess(), 8, ctypes.byref(token)):
            raise ctypes.WinError(ctypes.get_last_error())
        required = wintypes.DWORD()
        advapi.GetTokenInformation(token, 1, None, 0, ctypes.byref(required))
        if not required.value:
            raise ctypes.WinError(ctypes.get_last_error())
        buffer = ctypes.create_string_buffer(required.value)
        if not advapi.GetTokenInformation(token, 1, buffer, required, ctypes.byref(required)):
            raise ctypes.WinError(ctypes.get_last_error())
        sid = ctypes.cast(buffer, ctypes.POINTER(ctypes.c_void_p))[0]
        if not advapi.ConvertSidToStringSidW(sid, ctypes.byref(sid_text)):
            raise ctypes.WinError(ctypes.get_last_error())
        sddl = f"D:P(A;OICI;FA;;;{sid_text.value})(A;OICI;FA;;;SY)"
        if not advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl, 1, ctypes.byref(descriptor), None
        ) or not advapi.SetFileSecurityW(str(path), 0x80000004, descriptor):
            raise ctypes.WinError(ctypes.get_last_error())
    finally:
        if descriptor:
            kernel.LocalFree(descriptor)
        if sid_text:
            kernel.LocalFree(ctypes.cast(sid_text, ctypes.c_void_p))
        if token:
            kernel.CloseHandle(token)


def validate_pcap(path, count):
    """Bound classic PCAP record allocations and reject incomplete input."""
    path = Path(path)
    if os.name == "nt" and str(path.absolute()).startswith("\\\\"):
        raise ValueError("Offline input must be a local file")
    if os.name == "nt":
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.GetDriveTypeW.argtypes = [wintypes.LPCWSTR]
        if kernel.GetDriveTypeW(path.absolute().anchor) == 4:
            raise ValueError("Offline input must not be on a mapped network drive")
    if not path.is_file():
        raise ValueError("Offline input must be a regular file")
    size = path.stat().st_size
    with path.open("rb") as stream:
        header = stream.read(24)
        formats = {
            b"\xd4\xc3\xb2\xa1": "<",
            b"\xa1\xb2\xc3\xd4": ">",
            b"\x4d\x3c\xb2\xa1": "<",
            b"\xa1\xb2\x3c\x4d": ">",
        }
        if len(header) != 24 or header[:4] not in formats:
            raise ValueError("Expected classic PCAP (convert PCAPNG to PCAP first)")
        endian = formats[header[:4]]
        _, major, minor, _, _, snaplen, _ = struct.unpack(endian + "IHHIIII", header)
        if (major, minor) != (2, 4) or not 0 < snaplen <= 1048576:
            raise ValueError("Unsupported PCAP version or snapshot length")
        for _ in range(count):
            record = stream.read(16)
            if not record:
                break
            if len(record) != 16:
                raise ValueError("Incomplete PCAP record header")
            _, _, caplen, wirelen = struct.unpack(endian + "IIII", record)
            if (
                caplen > MAX_PACKET_BYTES
                or caplen > snaplen
                or caplen > wirelen
                or stream.tell() + caplen > size
            ):
                raise ValueError("Invalid or incomplete PCAP record")
            stream.seek(caplen, 1)


class LimitedPcapFile:
    """Bound actual reads too, even if input changes after preflight."""

    def __init__(self, stream):
        self.stream = stream

    def read(self, size=-1):
        if not 0 <= size <= MAX_PACKET_BYTES:
            raise ValueError("PCAP requested an oversized read")
        return self.stream.read(size)

    def __getattr__(self, name):
        return getattr(self.stream, name)


class BurstTracker:
    """Sliding window with bounded state and one indicator per window."""

    def __init__(self, threshold, window, max_keys=1024):
        self.threshold, self.window, self.max_keys = threshold, window, max_keys
        self.states = OrderedDict()
        self.last_time = None

    def observe(self, key, timestamp):
        if self.last_time is not None and timestamp < self.last_time:
            self.states.clear()
        self.last_time = timestamp
        cutoff = timestamp - self.window
        while self.states and next(iter(self.states.values()))[0][-1] <= cutoff:
            self.states.popitem(last=False)
        samples, last_alert = self.states.pop(key, (deque(maxlen=self.threshold), -math.inf))
        while samples and samples[0] <= cutoff:
            samples.popleft()
        samples.append(timestamp)
        alert = len(samples) >= self.threshold and timestamp - last_alert >= self.window
        self.states[key] = (samples, timestamp if alert else last_alert)
        if len(self.states) > self.max_keys:
            self.states.popitem(last=False)
        return alert


class ProcessResolver:
    """Cached local attribution. Historical packets never use this resolver."""

    def __init__(self, clock=time.monotonic):
        self.clock, self.refreshed = clock, -math.inf
        self.connections, self.errors = [], 0

    def resolve(self, row):
        now = self.clock()
        if now - self.refreshed >= 2:
            self.refreshed = now
            try:
                self.connections = psutil.net_connections(kind="inet")
            except (psutil.Error, OSError):
                self.connections = []
                self.errors += 1
        family = socket.AF_INET6 if row["ip_version"] == 6 else socket.AF_INET
        kind = socket.SOCK_STREAM if row["protocol"] == "TCP" else socket.SOCK_DGRAM
        candidates = set()
        for conn in self.connections:
            if conn.family != family or conn.type != kind or not conn.laddr or conn.pid is None:
                continue
            for local, remote in (("source", "destination"), ("destination", "source")):
                if conn.laddr.port != row[f"{local}_port"]:
                    continue
                bound = conn.laddr.ip.split("%", 1)[0]
                if bound not in (row[local], "0.0.0.0", "::"):
                    continue
                if conn.raddr:
                    if (conn.raddr.ip.split("%", 1)[0], conn.raddr.port) != (
                        row[remote],
                        row[f"{remote}_port"],
                    ):
                        continue
                elif bound in ("0.0.0.0", "::"):
                    continue  # A wildcard listener cannot establish ownership.
                candidates.add(conn.pid)
        if len(candidates) != 1:
            return None
        pid = candidates.pop()
        try:
            return {"pid": pid, "name": psutil.Process(pid).name(), "confidence": "best_effort"}
        except (psutil.Error, OSError):
            self.errors += 1
            return None


class PacketAssessment:
    """Analyze one packet at a time with bounded summary and rule state."""

    def __init__(
        self,
        config_dir=DATA_DIRECTORY,
        include_payload=False,
        resolver=None,
        syn_threshold=100,
        udp_threshold=500,
        window=10,
    ):
        self.whitelist, self.keywords, self.services, self.ranges = load_config(config_dir)
        self.include_payload, self.resolver = include_payload, resolver
        self.syn = BurstTracker(syn_threshold, window)
        self.udp = BurstTracker(udp_threshold, window)
        self.total, self.errors = 0, 0
        self.protocols, self.indicators = Counter(), Counter()
        self.sources, self.destinations, self.flows = set(), set(), set()
        self.identities_truncated = False
        self.first_timestamp = self.last_timestamp = None

    def port_hint(self, port):
        if port is None:
            return None
        if str(port) in self.services:
            return self.services[str(port)]
        for item in self.ranges:
            if item["start"] <= port <= item["end"]:
                return item["name"]
        return None

    def remember(self, collection, value):
        if value is None or value in collection:
            return
        if len(collection) < MAX_IDENTITIES:
            collection.add(value)
        else:
            self.identities_truncated = True

    def analyze(self, packet):
        timestamp = float(packet.time)
        if not math.isfinite(timestamp):
            raise ValueError("Invalid packet timestamp")
        self.total += 1
        self.first_timestamp = (
            timestamp if self.first_timestamp is None else min(self.first_timestamp, timestamp)
        )
        self.last_timestamp = (
            timestamp if self.last_timestamp is None else max(self.last_timestamp, timestamp)
        )
        row = {
            "number": self.total,
            "timestamp": timestamp,
            "protocol": "OTHER",
            "ip_version": None,
            "source": None,
            "destination": None,
            "source_port": None,
            "destination_port": None,
            "frame_length": len(packet),
            "wire_length": packet.wirelen,
            "truncated": packet.wirelen is not None and packet.wirelen > len(packet),
            "process": None,
        }
        if Ether in packet:
            row.update(source_mac=packet[Ether].src, destination_mac=packet[Ether].dst)
        network = None
        current = packet
        while not isinstance(current, NoPayload):
            if isinstance(current, (IP, IPv6, ARP)):
                network = current
                break
            current = current.payload
        transport = None
        if isinstance(network, ARP):
            row.update(protocol="ARP", source=network.psrc, destination=network.pdst)
        elif isinstance(network, (IP, IPv6)):
            version = 4 if isinstance(network, IP) else 6
            row.update(ip_version=version, source=network.src, destination=network.dst)
            if version == 4:
                header = (network.ihl or 5) * 4
                row.update(
                    ip_header_length=header,
                    ip_total_length=network.len or len(network),
                    protocol=f"IP/{network.proto}",
                )
            else:
                size = network.plen if network.plen is not None else len(network.payload)
                row.update(
                    ip_header_length=40,
                    ip_payload_length=size,
                    ip_total_length=40 + size,
                    protocol=f"IPv6/{network.nh}",
                )
            current = network.payload
            while not isinstance(current, NoPayload):
                if isinstance(current, (IP, IPv6)):
                    break
                if isinstance(current, (TCP, UDP)):
                    transport = current
                    break
                current = current.payload
        payload = b""
        if transport is not None:
            protocol = "TCP" if isinstance(transport, TCP) else "UDP"
            payload = bytes(transport.payload)
            row.update(
                protocol=protocol,
                source_port=transport.sport,
                destination_port=transport.dport,
                payload_length=len(payload),
                source_port_hint=self.port_hint(transport.sport),
                destination_port_hint=self.port_hint(transport.dport),
            )
            if protocol == "TCP":
                row.update(
                    sequence=transport.seq,
                    acknowledgment=transport.ack,
                    window=transport.window,
                    tcp_flags=str(transport.flags),
                )
            if self.include_payload:
                row["payload_base64"] = base64.b64encode(payload).decode("ascii")
            if self.resolver:
                row["process"] = self.resolver.resolve(row)
        row["whitelisted"] = row["source"] in self.whitelist or row["destination"] in self.whitelist
        self.protocols[row["protocol"]] += 1
        self.remember(self.sources, row["source"])
        self.remember(self.destinations, row["destination"])
        if transport is not None:
            self.remember(
                self.flows,
                (
                    row["ip_version"],
                    row["protocol"],
                    row["source"],
                    row["source_port"],
                    row["destination"],
                    row["destination_port"],
                ),
            )
        alerts = []

        def add(rule, detail):
            self.indicators[rule] += 1
            alerts.append(
                {
                    "rule": rule,
                    "detail": detail,
                    "packet_number": self.total,
                    "timestamp": timestamp,
                    "source": row["source"],
                    "destination": row["destination"],
                    "protocol": row["protocol"],
                    "classification": "experimental_indicator",
                }
            )

        # Whitelist suppresses indicators, not metadata/optional packet retention.
        if not row["whitelisted"] and transport is not None:
            key = (row["source"], row["destination"], row["destination_port"])
            if isinstance(transport, TCP) and int(transport.flags) & 2 and not int(transport.flags) & 16:
                if self.syn.observe(key, timestamp):
                    add("syn_burst", f"At least {self.syn.threshold} SYN packets in {self.syn.window:g}s")
            if isinstance(transport, UDP) and self.udp.observe(key, timestamp):
                add("udp_burst", f"At least {self.udp.threshold} UDP packets in {self.udp.window:g}s")
            scan = payload[:MAX_SCAN_BYTES].lower()
            for keyword in self.keywords:
                if keyword.encode("utf-8").lower() in scan:
                    add("payload_keyword", f"Configured keyword matched: {keyword}")
            if DNS in transport:
                dns = transport[DNS]
                # Scapy 2.5 linked records and newer packet-list answers.
                answers = dns.an
                records = answers if isinstance(answers, list) else []
                if not isinstance(answers, list):
                    record = answers
                    for _ in range(min(int(dns.ancount or 0), 256)):
                        if not record or isinstance(record, NoPayload):
                            break
                        records.append(record)
                        record = record.payload
                for record in records[:256]:
                    if getattr(record, "type", None) == 16:
                        data = record.rdata
                        size = sum(len(x) for x in data) if isinstance(data, list) else len(data)
                        if size > 200:
                            add("long_dns_txt", f"DNS TXT answer contains {size} bytes")
                            break
        return row, alerts

    def summary(self):
        return {
            "packets_seen": self.total,
            "packet_errors": self.errors,
            "protocol_counts": dict(self.protocols),
            "indicator_counts": dict(self.indicators),
            "source_addresses": sorted(self.sources),
            "destination_addresses": sorted(self.destinations),
            "unique_addresses": len(self.sources | self.destinations),
            "unique_flows": len(self.flows),
            "identity_counts_are_lower_bounds": self.identities_truncated,
            "first_packet_timestamp": self.first_timestamp,
            "last_packet_timestamp": self.last_timestamp,
            "capture_span_seconds": (self.last_timestamp - self.first_timestamp)
            if self.first_timestamp is not None
            else 0,
            "process_lookup_errors": self.resolver.errors if self.resolver else 0,
        }


class SessionOutput:
    """Incremental files in a new private session; no retained packet list."""

    def __init__(self, directory, save_pcap=False):
        base = secure_directory(directory)
        self.directory = secure_directory(
            base / (datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ-") + uuid.uuid4().hex[:12])
        )
        self.rows = self.alerts = self.pcap = None
        self.closed = False
        try:
            self.rows = (self.directory / "packets.jsonl").open("x", encoding="utf-8")
            self.alerts = (self.directory / "indicators.jsonl").open("x", encoding="utf-8")
            if save_pcap:
                self.pcap = PcapWriter(str(self.directory / "capture.pcap"), sync=True)
        except Exception:
            self.close()
            raise

    def write(self, packet, row, alerts):
        self.rows.write(json.dumps(row, ensure_ascii=True) + "\n")
        self.rows.flush()
        for alert in alerts:
            self.alerts.write(json.dumps(alert, ensure_ascii=True) + "\n")
        self.alerts.flush()
        if self.pcap:
            self.pcap.write(packet)

    def close(self):
        if self.closed:
            return []
        self.closed = True
        failures = []
        for stream in (self.rows, self.alerts, self.pcap):
            if stream is not None:
                try:
                    stream.close()
                except Exception as exc:
                    failures.append(str(exc))
        return failures

    def finish(self, summary):
        failures = self.close()
        if failures:
            summary["status"] = "failed"
            summary["close_errors"] = failures
        temporary = self.directory / "summary.json.tmp"
        with temporary.open("x", encoding="utf-8") as stream:
            json.dump(summary, stream, indent=2)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, self.directory / "summary.json")
        if failures:
            raise OSError("Output close failed: " + "; ".join(failures))


def default_output_directory():
    if os.name == "nt":
        local = os.environ.get("LOCALAPPDATA")
        if not local:
            raise ValueError("LOCALAPPDATA is unavailable; supply --output-dir")
        return Path(local) / "Foocap" / "captures"
    return Path.home() / ".local" / "share" / "foocap" / "captures"


def positive_int(value):
    result = int(value)
    if not 1 <= result <= 10000000:
        raise argparse.ArgumentTypeError("must be between 1 and 10000000")
    return result


def positive_seconds(value):
    result = float(value)
    if not math.isfinite(result) or not 0 < result <= 86400:
        raise argparse.ArgumentTypeError("must be finite and between 0 and 86400 seconds")
    return result


def build_parser():
    parser = argparse.ArgumentParser(
        description="Foocap passive packet inspection. Indicators are experimental."
    )
    parser.add_argument("--read", type=Path, metavar="PCAP", help="analyze a local PCAP without live capture")
    parser.add_argument("--iface", help="capture interface (required for live capture)")
    parser.add_argument("--list-interfaces", action="store_true", help="list interfaces and exit; no capture")
    parser.add_argument("--filter", default="", help="live BPF filter; unavailable with --read")
    parser.add_argument(
        "--duration", type=positive_seconds, default=60, help="maximum live seconds (default 60)"
    )
    parser.add_argument("--count", type=positive_int, default=10000, help="maximum packets (default 10000)")
    parser.add_argument(
        "--output-dir", type=Path, help="dedicated local directory; permissions will be restricted"
    )
    parser.add_argument("--config-dir", type=Path, default=DATA_DIRECTORY)
    parser.add_argument(
        "--include-payload", action="store_true", help="retain payload bytes as base64 in JSONL"
    )
    parser.add_argument(
        "--save-pcap", action="store_true", help="retain full raw packets, including payloads"
    )
    parser.add_argument(
        "--processes", action="store_true", help="best-effort local process attribution (live only)"
    )
    parser.add_argument("--syn-threshold", type=positive_int, default=100)
    parser.add_argument("--udp-threshold", type=positive_int, default=500)
    parser.add_argument(
        "--window", type=positive_seconds, default=10, help="indicator window seconds (default 10)"
    )
    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.read and (args.iface or args.filter or args.processes or args.list_interfaces):
        parser.error("--read cannot be combined with live interface, filter, or process options")
    if max(args.syn_threshold, args.udp_threshold) > 10000:
        parser.error("indicator thresholds must not exceed 10000")
    if args.list_interfaces:
        try:
            from scapy.arch import get_if_list

            for interface in get_if_list():
                print(interface)
            return 0
        except Exception as exc:
            print(f"Cannot list interfaces: {exc}", file=sys.stderr)
            return 1
    if not args.read and not args.iface:
        parser.error("choose --read PCAP, --list-interfaces, or --iface INTERFACE")
    output = None
    status, failure = "completed", None
    started = time.monotonic()
    try:
        assessment = PacketAssessment(
            args.config_dir,
            args.include_payload,
            ProcessResolver() if args.processes else None,
            args.syn_threshold,
            args.udp_threshold,
            args.window,
        )
        if args.read:
            validate_pcap(args.read, args.count)
        reader = None
        if args.read:
            stream = args.read.open("rb")
            try:
                reader = PcapReader(LimitedPcapFile(stream))
            except BaseException:
                stream.close()
                raise
        try:
            output = SessionOutput(args.output_dir or default_output_directory(), args.save_pcap)
            capture_error = None

            def consume(packet):
                nonlocal capture_error
                try:
                    row, alerts = assessment.analyze(packet)
                except Exception as exc:
                    assessment.errors += 1
                    capture_error = f"Packet analysis failed: {type(exc).__name__}"
                    return
                try:
                    output.write(packet, row, alerts)
                except Exception as exc:
                    capture_error = f"Packet output failed: {exc}"

            if reader is not None:
                for number, packet in enumerate(reader):
                    consume(packet)
                    if capture_error:
                        raise RuntimeError(capture_error)
                    if number + 1 >= args.count:
                        break
            else:
                from scapy.sendrecv import sniff

                print(
                    f"Capturing on {args.iface} for up to {args.duration:g}s / {args.count} packets. Ctrl+C stops."
                )
                if args.include_payload or args.save_pcap:
                    print("Payload retention enabled. Keep these outputs private.")
                capture_started = time.monotonic()
                sniff(
                    iface=args.iface,
                    filter=args.filter or None,
                    prn=consume,
                    store=False,
                    timeout=args.duration,
                    count=args.count,
                    chainCC=True,
                    stop_filter=lambda packet: capture_error is not None,
                )
                if capture_error:
                    raise RuntimeError(capture_error)
                if assessment.total < args.count and time.monotonic() - capture_started < args.duration - 0.5:
                    raise RuntimeError("Capture ended before its limits; check capture-driver errors")
        finally:
            if reader is not None:
                reader.close()
    except KeyboardInterrupt:
        status = "interrupted"
    except Exception as exc:
        status, failure = "failed", str(exc)
        print(f"Foocap failed: {exc}", file=sys.stderr)
        if not args.read:
            print(
                "Check the interface, Npcap installation/access policy, filter, and output permissions.",
                file=sys.stderr,
            )
    finally:
        if output is not None:
            summary = assessment.summary()
            summary.update(
                status=status,
                error=failure,
                mode="offline" if args.read else "live",
                processing_seconds=round(time.monotonic() - started, 3),
                payload_retained=args.include_payload,
                raw_pcap_retained=args.save_pcap,
                limits={"packets": args.count, "live_seconds": args.duration},
                indicator_settings={
                    "window_seconds": args.window,
                    "syn_threshold": args.syn_threshold,
                    "udp_threshold": args.udp_threshold,
                },
            )
            try:
                output.finish(summary)
                print(f"Results: {output.directory}")
                print(
                    f"Packets: {assessment.total}; indicators: {sum(assessment.indicators.values())}; status: {status}"
                )
            except Exception as exc:
                status = "failed"
                print(f"Could not finalize output: {exc}. Partial files: {output.directory}", file=sys.stderr)
    return 1 if status == "failed" else 130 if status == "interrupted" else 0


if __name__ == "__main__":
    raise SystemExit(main())
