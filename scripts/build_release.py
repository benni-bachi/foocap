"""Build an explicit source allowlist, excluding local captures and environments."""

import argparse
import hashlib
import json
from pathlib import Path
import zipfile

ROOT = Path(__file__).resolve().parents[1]
FILES = (
    ".gitignore",
    ".github/workflows/tests.yml",
    "README.md",
    "VALIDATION.md",
    "capture.py",
    "requirements.txt",
    "requirements-dev.txt",
    "pyproject.toml",
    "PacketReader/Scripts/Capture.py",
    "PacketReader/Scripts/Data/Services.json",
    "PacketReader/Scripts/Data/SuspisciousKeywords.json",
    "PacketReader/Scripts/Data/Whitelist.json",
    "scripts/make_demo.py",
    "scripts/build_release.py",
    "tests/test_capture.py",
    "tests/test_release.py",
)


def check_release(root=ROOT):
    root = Path(root)
    for name in FILES:
        path = root / name
        if path.is_symlink() or not path.is_file() or path.resolve() != root.resolve() / name:
            raise ValueError(f"Invalid/missing release file: {name}")
    whitelist = json.loads((root / "PacketReader/Scripts/Data/Whitelist.json").read_text(encoding="utf-8"))
    if whitelist != {"Whitelist": []}:
        raise ValueError("Public release whitelist must be empty")
    for name in FILES:
        if Path(name).suffix in {".pcap", ".pcapng", ".jsonl"} or ".private-captures" in name:
            raise ValueError(f"Private artifact in allowlist: {name}")
    return {name: hashlib.sha256((root / name).read_bytes()).hexdigest() for name in FILES}


def build_release(root=ROOT):
    hashes = check_release(root)
    target = Path(root) / "dist/foocap-source.zip"
    target.parent.mkdir(exist_ok=True)
    temporary = target.with_suffix(".zip.tmp")
    with zipfile.ZipFile(temporary, "w", zipfile.ZIP_DEFLATED) as archive:
        for name in FILES:
            archive.write(Path(root) / name, name)
        archive.writestr("RELEASE-MANIFEST.json", json.dumps(hashes, indent=2))
    temporary.replace(target)
    return target


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="validate source allowlist without packaging")
    args = parser.parse_args()
    if args.check:
        print(f"Release allowlist passed: {len(check_release())} files; no captures/environment included")
    else:
        print(build_release())
