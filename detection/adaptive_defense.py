#!/usr/bin/env python3

import json
import subprocess
from datetime import datetime


INTELLIGENCE_FILE = "detection/validated_intelligence.json"
CHAIN = "WALL2"


def ensure_chain():
    result = subprocess.run(
        ["iptables", "-L", CHAIN],
        capture_output=True
    )

    if result.returncode != 0:
        subprocess.run(
            ["iptables", "-N", CHAIN],
            check=True
        )

        print(f"[WALL2] Created chain {CHAIN}")


def block_source(source_ip):
    check = subprocess.run(
        [
            "iptables",
            "-C",
            CHAIN,
            "-s",
            source_ip,
            "-j",
            "DROP"
        ],
        capture_output=True
    )

    if check.returncode == 0:
        print(f"[WALL2] {source_ip} is already blocked.")
        return

    subprocess.run(
        [
            "iptables",
            "-A",
            CHAIN,
            "-s",
            source_ip,
            "-j",
            "DROP"
        ],
        check=True
    )

    print(
        f"[WALL2] {datetime.now()} | "
        f"BLOCKED source={source_ip}"
    )


def main():

    print("Resolute - Adaptive Wall 2\n")

    try:
        with open(INTELLIGENCE_FILE, "r") as file:
            profile = json.load(file)

    except FileNotFoundError:
        print("No validated intelligence found.")
        print("Wall 2 will take NO action.")
        return

    status = profile.get("threat_status")
    source_ip = profile.get("source_ip")

    print(f"Threat status: {status}")
    print(f"Source IP: {source_ip}")

    if status != "VALIDATED_THREAT":
        print("\n[WALL2] Threat is not validated.")
        print("[WALL2] No defensive action taken.")
        return

    ensure_chain()

    block_source(source_ip)

    print("\n[WALL2] Adaptive defense applied.")
    print("[WALL2] Reason: validated threat intelligence.")


if __name__ == "__main__":
    main()
