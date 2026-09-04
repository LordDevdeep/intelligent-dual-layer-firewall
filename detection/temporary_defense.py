#!/usr/bin/env python3

import json
import subprocess
import time
from datetime import datetime


INTELLIGENCE_FILE = "detection/validated_intelligence.json"
CHAIN = "WALL2"
BLOCK_DURATION = 60


def rule_exists(source_ip):

    result = subprocess.run(
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

    return result.returncode == 0


def add_block(source_ip):

    if rule_exists(source_ip):
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
        f"BLOCKED {source_ip}"
    )


def remove_block(source_ip):

    if not rule_exists(source_ip):
        print(f"[WALL2] No active block found for {source_ip}.")
        return

    subprocess.run(
        [
            "iptables",
            "-D",
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
        f"ROLLBACK completed for {source_ip}"
    )


def main():

    print("Resolute - Temporary Adaptive Defense\n")

    try:
        with open(INTELLIGENCE_FILE, "r") as file:
            profile = json.load(file)

    except FileNotFoundError:
        print("No validated intelligence found.")
        print("No defensive action taken.")
        return

    status = profile.get("threat_status")
    source_ip = profile.get("source_ip")

    print(f"Threat status: {status}")
    print(f"Source IP: {source_ip}")

    if status != "VALIDATED_THREAT":
        print("\n[WALL2] Threat is not validated.")
        print("[WALL2] No defensive action taken.")
        return

    add_block(source_ip)

    print(
        f"\n[WALL2] Temporary block active for "
        f"{BLOCK_DURATION} seconds."
    )

    print("[WALL2] Rollback timer started...")

    time.sleep(BLOCK_DURATION)

    remove_block(source_ip)

    print("\n[WALL2] Adaptive defense cycle completed.")


if __name__ == "__main__":
    main()
