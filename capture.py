"""Run Foocap from the repository root."""

import sys

try:
    from PacketReader.Scripts.Capture import main
except ModuleNotFoundError as exc:
    if exc.name not in {"scapy", "psutil"} and not exc.name.startswith("scapy."):
        raise
    print("Install Foocap dependencies: python -m pip install -r requirements.txt", file=sys.stderr)
    raise SystemExit(1) from exc

if __name__ == "__main__":
    raise SystemExit(main())
