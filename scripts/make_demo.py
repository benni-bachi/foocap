"""Create documentation-only synthetic packets. Never sends traffic."""

import argparse
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from PacketReader.Scripts.Capture import secure_directory  # noqa: E402
from scapy.layers.dns import DNS, DNSQR, DNSRR  # noqa: E402
from scapy.layers.inet import IP, TCP, UDP  # noqa: E402
from scapy.layers.l2 import Ether  # noqa: E402
from scapy.packet import Raw  # noqa: E402
from scapy.utils import PcapWriter  # noqa: E402


def make_demo(path):
    path = Path(path)
    secure_directory(path.parent)
    if path.exists():
        raise FileExistsError(f"Refusing to overwrite {path}")
    network = IP(src="192.0.2.10", dst="198.51.100.20")
    layers = [network / TCP(sport=40000 + i, dport=443, flags="S") for i in range(3)]
    layers += [network / UDP(sport=41000, dport=9999) / Raw(b"synthetic") for _ in range(3)]
    layers += [
        network / TCP(sport=40010, dport=80, flags="PA") / Raw(b"login=synthetic-demo"),
        network
        / UDP(sport=53, dport=41000)
        / DNS(
            qr=1, qd=DNSQR(qname="example.test"), an=DNSRR(rrname="example.test", type=16, rdata=[b"x" * 201])
        ),
        network / TCP(flags="FA", seq=10, ack=20),
        network / TCP(flags="RA", window=0),
    ]
    with PcapWriter(str(path), linktype=1, sync=True) as writer:
        for index, layer in enumerate(layers):
            packet = Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02") / layer
            packet.time = 1700000000 + index * 0.1
            writer.write(packet)
    return path


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path("captures/demo.pcap"))
    args = parser.parse_args()
    print(make_demo(args.output))
