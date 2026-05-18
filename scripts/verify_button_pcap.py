#!/usr/bin/env python3
"""Regression check: PCAP button bursts match button_notify rules."""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# 48-byte UDP payloads (from tshark data field) observed in project captures.
# From scansnap_org_button_test.pcapng (tshark data field, 48 bytes)
FIXTURE_BUTTON_9 = bytes.fromhex(
    "0000003056454e5300000001000000000900000000000000000000000000000000000000000000000000000000000000"
)
FIXTURE_BROADCAST = bytes.fromhex(
    "0000003056454e5300000021000000000000000000000000000000000000000000000000000000000000000000000000"
)


def tshark_path() -> str:
    found = shutil.which("tshark")
    if found:
        return found
    mac = "/Applications/Wireshark.app/Contents/MacOS/tshark"
    if Path(mac).is_file():
        return mac
    raise FileNotFoundError("tshark not found")


def run_tshark(pcap: Path) -> list[list[str]]:
    cmd = [
        tshark_path(),
        "-r",
        str(pcap),
        "-Y",
        "udp.dstport == 55265 && data.len == 48",
        "-T",
        "fields",
        "-e",
        "frame.time_relative",
        "-e",
        "data",
    ]
    result = subprocess.run(cmd, check=True, capture_output=True, text=True)
    rows = []
    for line in result.stdout.splitlines():
        if not line.strip():
            continue
        parts = line.split("\t")
        if len(parts) != 2:
            continue
        rows.append(parts)
    return rows


def is_button_notify(payload: bytes) -> bool:
    if len(payload) != 48:
        return False
    if payload[4:8] != b"VENS":
        return False
    if int.from_bytes(payload[8:12], "big") != 1:
        return False
    return True


def counter(payload: bytes) -> int:
    if not is_button_notify(payload):
        return 0
    return int.from_bytes(payload[16:20], "little")


def test_fixtures() -> None:
    assert is_button_notify(FIXTURE_BUTTON_9)
    assert counter(FIXTURE_BUTTON_9) == 9
    assert not is_button_notify(FIXTURE_BROADCAST)


def analyze_pcap(pcap: Path) -> list[int]:
    counters = []
    for _time, data_hex in run_tshark(pcap):
        payload = bytes.fromhex(data_hex.replace(":", ""))
        if is_button_notify(payload):
            counters.append(counter(payload))
    return counters


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "pcap",
        nargs="*",
        type=Path,
        help="pcapng files (default: scansnap_org_button_test.pcapng if present)",
    )
    args = parser.parse_args()

    test_fixtures()
    print("fixtures OK", file=sys.stderr)

    pcaps = args.pcap
    if not pcaps:
        default = ROOT / "scansnap_org_button_test.pcapng"
        if default.is_file():
            pcaps = [default]
        else:
            print("no pcap given and default missing; fixtures-only OK", file=sys.stderr)
            return 0

    for pcap in pcaps:
        if not pcap.is_file():
            print(f"skip missing {pcap}", file=sys.stderr)
            continue
        counters = analyze_pcap(pcap)
        print(f"{pcap.name}: {len(counters)} notify packet(s), counters={counters}")
        if pcap.name == "scansnap_org_button_test.pcapng":
            if counters != [9, 9, 9, 10, 10, 10]:
                print(
                    f"unexpected counters for button_test: {counters}",
                    file=sys.stderr,
                )
                return 1
            print(f"{pcap.name}: OK (two button bursts)", file=sys.stderr)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
