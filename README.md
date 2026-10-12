# Foocap

Foocap is a lightweight, Windows-oriented tool for passive packet inspection and offline PCAP analysis. It streams packet metadata to local files and highlights a small set of experimental security indicators. Its Python runtime dependencies are Scapy and psutil.

Foocap does not intercept connections, modify traffic, decrypt TLS, or block attacks. An indicator is an observation for investigation, not evidence that an attack occurred.

## Windows 11 setup

Use 64-bit Python 3.12 with this release. Python 3.12 and the pinned dependencies were exercised by the offline suite; the configured CI also targets Python 3.13. Live driver compatibility still needs the smoke test below.

From the project root in PowerShell:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe capture.py --help
```

Install [Npcap](https://npcap.com/#download) separately for live capture, following [Scapy's Windows installation guidance](https://scapy.readthedocs.io/en/stable/installation.html#windows). Do not install legacy WinPcap alongside it. Wireshark and Nmap are not application dependencies.

Npcap's administrator-only option controls capture access. If enabled, opening a capture handle requires elevation; otherwise follow your machine's access policy. Foocap does not change that policy or elevate itself. Driver installation requires the appropriate Windows permissions. See the [Npcap users' guide](https://npcap.com/guide/npcap-users-guide.html).

There is no need to change PowerShell's execution policy: the commands invoke the virtual environment's Python directly.

## Try it without capturing traffic

The demo generator creates ten artificial packets using documentation addresses, fixed MAC addresses, and synthetic content. It sends nothing and requires no capture driver.

```powershell
.\.venv\Scripts\python.exe scripts\make_demo.py
.\.venv\Scripts\python.exe capture.py --read captures\demo.pcap --output-dir captures\demo-results --syn-threshold 3 --udp-threshold 3
```

Expected summary: 10 packets and one indicator each for `syn_burst`, `udp_burst`, `payload_keyword`, and `long_dns_txt`. The generator refuses to overwrite an existing demo file. Demo outputs are ignored by Git.

## Live inspection

Inspect only traffic you are authorized to capture. List interfaces, then copy the exact interface identifier into the capture command:

```powershell
.\.venv\Scripts\python.exe capture.py --list-interfaces
.\.venv\Scripts\python.exe capture.py --iface "INTERFACE_FROM_LIST" --duration 60 --count 10000
```

Both limits apply: capture stops at 60 seconds or 10,000 packets, whichever comes first. Ctrl+C finalizes partial results. A filter can reduce the traffic processed:

```powershell
.\.venv\Scripts\python.exe capture.py --iface "INTERFACE_FROM_LIST" --filter "tcp port 443" --duration 30
```

Capturing port 443 provides metadata and encrypted payload bytes; it does not reveal decrypted HTTPS content. Interface visibility depends on your network topology and driver. Promiscuous capture cannot make a switched network's unrelated traffic visible by itself. Wireless monitor mode is not configured by this tool.

Process attribution is optional:

```powershell
.\.venv\Scripts\python.exe capture.py --iface "INTERFACE_FROM_LIST" --processes
```

This matches current local endpoints in both directions, distinguishes TCP/UDP and IPv4/IPv6, and caches socket snapshots for two seconds. Missing permissions, process races, ambiguous endpoints, and unconnected wildcard sockets return unknown. Results are explicitly best effort. No complete process inventory is collected. Historical PCAP packets never receive current-process attribution.

## Outputs and privacy

Default Windows output: `%LOCALAPPDATA%\Foocap\captures\SESSION_ID\`. Every run creates a new session. Output directories receive a protected ACL granting access to the current user and SYSTEM before any packet data is written. Foocap fails if it cannot apply that protection. An administrator can still take ownership; this is access control, not encryption.

`--output-dir` must identify a **dedicated local directory**, because Foocap restricts its permissions. Do not supply a shared folder or the project root. Home/project roots, links, junctions, UNC paths, and mapped network drives are rejected. The non-Windows fallback uses a private directory mode, but live operation on other operating systems is not release-validated.

| File | Content |
| --- | --- |
| `packets.jsonl` | One metadata object per analyzed packet; payload bytes omitted by default |
| `indicators.jsonl` | Experimental indicator records, linked by packet number |
| `summary.json` | Status, counts, unique addresses/flows, timing, limits, and rule settings |
| `capture.pcap` | Full packets, created only with `--save-pcap` |

`--include-payload` stores exact transport payload bytes as base64 in JSONL. `--save-pcap` retains full packets regardless of `--include-payload`. Base64 is not encryption. Both options can retain credentials or other private content.

Even metadata includes addresses, MACs, ports, timestamps, and optional process names. Outputs remain sensitive; keep them local and delete session folders when no longer needed. Foocap does not upload data and does not automatically expire files.

Files are written incrementally and flushed per packet. The final summary is replaced atomically. A crash or power loss can leave partial JSONL/PCAP files without a summary; storage exhaustion returns failure. There is no promise of complete packet delivery under load.

Exit codes: `0` completed, `1` failure, `2` invalid arguments, `130` interrupted. A failed session's summary identifies failure if it could be finalized. Always check status before interpreting results.

## Indicators and configuration

Configuration is loaded once from `PacketReader/Scripts/Data`, independently of the working directory. Invalid or missing configuration fails clearly and never recreates/overwrites files. Use `--config-dir` to load a private copy of all three configuration files.

| Rule | Default observation | Limitations |
| --- | --- | --- |
| `syn_burst` | At least 100 TCP SYN packets without ACK from one source to one destination/port in 10 seconds | Retransmissions, busy clients, and legitimate scans can match; no handshake tracking |
| `udp_burst` | At least 500 UDP packets from one source to one destination/port in 10 seconds | Games, voice/video, and other legitimate workloads can match; packet size is not an attack criterion |
| `long_dns_txt` | DNS TXT answer contains more than 200 bytes | Many legitimate TXT records are long; encrypted DNS is not inspected |
| `payload_keyword` | Configured UTF-8 keyword appears in the first 65,536 bytes of one TCP/UDP payload | Common words generate noise; no stream reassembly, semantic parsing, or TLS decryption |

`--syn-threshold`, `--udp-threshold`, and `--window` tune the burst observations. Burst state tracks at most 1,024 endpoint keys per rule, caps samples per key, expires old samples, and emits at most one indicator per key per window. Out-of-order packet timestamps reset that rule's state. Eviction can cause missed indicators; these rules are not an IDS.

`Whitelist.json` contains `{"Whitelist": []}`. Matching either endpoint **suppresses indicators only**; metadata and explicitly requested PCAP/payload retention still occur. Entries must be exact valid IP addresses. Keep personal whitelists outside the repository.

`SuspisciousKeywords.json` retains the original filename for compatibility, with a `Keywords` list. Indicator records contain the matched configured keyword, never a payload excerpt. `Services.json` provides **port hints**, not verified application identities; the broad RTP range was removed.

The former SSH tunneling, session hijacking, SMB attack, SMTP attack, RST attack, IPv6 fragmentation attack, and Slowloris labels were removed: their original conditions did not establish those attacks.

Summary address/flow sets are capped at 10,000 entries each; `identity_counts_are_lower_bounds` is set when a cap is reached. Flows are directional transport tuples. IPv6 `ip_header_length` means the 40-byte base header, excluding extension headers. `timestamp` comes from the packet; `processing_seconds` is wall-clock processing duration. Truncated captured frames are marked. There is no fragment or stream reassembly.

## Offline files

```powershell
.\.venv\Scripts\python.exe capture.py --read "C:\path\sample.pcap" --count 10000
```

Offline mode uses local classic PCAP files, opens no capture socket, and does not enumerate local connections. `--iface`, `--filter`, and `--processes` cannot be combined with it. The packet count limit applies; `--duration` applies only to live capture. PCAPNG and compressed captures are not supported; convert them to classic PCAP first. Selected records must be complete and no larger than 65,535 captured bytes; snapshot lengths above 1 MiB are rejected. Actual reads are also bounded if an input changes after validation. Malformed data fails with partial results preserved when possible.

Both `python capture.py ...` and `python PacketReader\Scripts\Capture.py ...` work; use the virtual environment's interpreter to ensure the pinned dependencies are selected. The output schema intentionally differs from the original single JSON report: JSONL avoids retaining a full session in memory.

## Development and public release

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
.\.venv\Scripts\python.exe -m ruff check .
.\.venv\Scripts\python.exe -B -m unittest discover -s tests -v
.\.venv\Scripts\python.exe -B scripts\build_release.py
```

The release builder creates `dist\foocap-source.zip` from an explicit source allowlist and includes a SHA-256 manifest. It excludes captures, outputs, virtual environments, and personal local files, and refuses a nonempty public whitelist. Use this sanitized source snapshot when preparing GitHub. Do not upload the entire local working folder through GitHub's web uploader.

Original local capture artifacts, when present, are preserved under ignored `.private-captures`; they are not part of the release. `.gitignore` does not remove files from any previous Git history. No prior repository history was available during preparation.

See [VALIDATION.md](VALIDATION.md) for completed checks and the remaining Windows live smoke test. No live capture or attack-validation claim is made by this release. Select a license before inviting third-party reuse; this source snapshot does not include a license grant.
