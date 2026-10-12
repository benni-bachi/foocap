# Release validation

## Completed locally

- Windows / Python 3.12.0 virtual environment with pinned Scapy 2.7.0, psutil 7.2.2, and development linter Ruff 0.14.0.
- Offline regression suite covers configuration integrity, keyword schemas, malformed configuration, protocol parsing, IPv6 and encapsulation, field values, binary payload opt-in, DNS TXT handling, burst windows/state caps, whitelist semantics, mocked process attribution, interrupted/failed output, malformed PCAP input, private Windows ACLs, session isolation, launchers, synthetic demo, and release packaging.
- All capture and process APIs are mocked in live-path tests. Synthetic PCAPs are generated locally; no packet is transmitted.
- The source archive uses an explicit allowlist; generated capture data and environments are excluded.

Local results on 2026-10-11:

| Check | Result |
| --- | --- |
| `python -B -m unittest discover -s tests -v` | 50 tests passed; no skips |
| `python -m ruff check .` | Passed |
| `python scripts/build_release.py --check` | Source allowlist passed |
| Packaged source extracted into an isolated temporary directory | All 50 tests passed again; manifest and archive file set verified |
| `python -m pip check` | No broken requirements |
| Synthetic demo | 10 packets; exactly four expected indicators |
| Windows output ACL | Current user + SYSTEM only on generated test output |
| Original captures | Preserved byte-for-byte in private quarantine; absent from public data directory |

ACL tests run under the normal Windows user account because the execution sandbox denies ACL updates; no administrator elevation or packet capture is involved. Scapy can issue route warnings for synthetic packets with implicit default addresses; those packets are only serialized in memory and never sent.

## Public GitHub CI

On 2026-10-12, the [Windows GitHub Actions run](https://github.com/benni-bachi/foocap/actions/runs/38286140007) passed on Python 3.12 and 3.13. Both jobs passed dependency installation, lint, all 50 offline regression tests, and the release allowlist check. The first run exposed an ARP fixture relying on local interface defaults; the fixture now supplies explicit synthetic MAC and IP addresses. No capture driver or live traffic is needed for this suite. Python 3.13 is verified in CI, not in the local development environment.

## Audit fixes

| Findings | Resolution |
| --- | --- |
| B1 | Original outputs moved to ignored private quarantine; empty public whitelist; explicit source-only archive |
| B2, I2 | Read-only validated configuration anchored to the module; cached service mappings; correct keyword extraction |
| B3, I5, I6 | Unsupported attack labels removed; four bounded/explicit experimental observations tested with synthetic traffic |
| I1 | Root launcher, pinned dependencies, Windows/Npcap instructions, clean source packaging |
| I3, I4 | Removed `tasklist` and full process inventory; optional cached endpoint matching, race/error handling, unknown PID rejection |
| I7 | Streaming JSONL/optional PCAP; bounded summary and indicator state; time/packet limits |
| I8 | Per-session names, incremental writes, independent stream closure, atomic summary, failure/interrupt exit codes |
| I9 | Private output ACL, payload opt-in, retention guidance, source ignore rules, local-only output paths |
| I10 | Actual TCP fields, IPv6 base-header lengths, distinct addresses/flows, packet timestamps, truncation markers |
| I11 | Exact optional payload encoding; packet-local byte matching and explicit reassembly/decryption limitations |
| I12 | Explicit whitelist suppression semantics; port labels presented as hints; broad RTP range removed |
| I13 | Offline regression tests and Windows CI configuration |

## Windows live smoke test — not performed

The preparation request prohibited live capture and elevated interception. Before describing Foocap as live-validated, perform these checks on your own authorized machine:

1. Install the documented environment and Npcap; record Python, package, Npcap, Windows, and adapter versions.
2. Run `capture.py --list-interfaces` and select an interface explicitly.
3. Capture your own normal traffic for 10 seconds using `--iface`, `--duration 10`, and `--count 1000`. Confirm completed status, valid JSONL, expected protocol counts, and private output permissions.
4. Stop another short run with Ctrl+C. Confirm interrupted status/exit 130 and readable partial outputs.
5. Test an invalid interface and invalid BPF filter. Confirm failure and a nonzero exit code.
6. If needed, enable `--processes` and compare a known local connection. Treat unknown attribution as expected, not proof of an error.
7. If using payload/PCAP retention, confirm the explicit options and keep outputs private. Remove test sessions after inspection.
8. Observe CPU/memory and whether capture loss occurs for your workload. No throughput claim should be made without measurement.

The indicators were verified against synthetic examples and benign counterexamples. No effectiveness, false-positive rate, attack coverage, or production IDS claim has been validated.
