import argparse
import ipaddress
import json
import subprocess
from pathlib import Path

DECISION_LOG = Path(
    "/home/lorddevdeep/resolute/experiments/phase5/live_test/phase6_decision_test.json"
)

CHAIN = "WALL2"


def valid_ip(value):
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def get_candidates():
    candidates = []

    if not DECISION_LOG.exists():
        return candidates

    with DECISION_LOG.open() as f:
        for line in f:
            if not line.strip():
                continue

            result = json.loads(line)

            if result.get("decision") != "BLOCK_CANDIDATE":
                continue

            source_ip = result.get("source_ip")

            if source_ip and valid_ip(source_ip):
                candidates.append(result)

    return candidates


def rule_exists(source_ip):
    result = subprocess.run(
        [
            "sudo",
            "iptables",
            "-C",
            CHAIN,
            "-s",
            source_ip,
            "-j",
            "DROP",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    return result.returncode == 0


def block(source_ip, apply):
    command = [
        "sudo",
        "iptables",
        "-I",
        CHAIN,
        "1",
        "-s",
        source_ip,
        "-j",
        "DROP",
    ]

    print("COMMAND:", " ".join(command))

    if not apply:
        print("DRY RUN: rule NOT applied")
        return

    result = subprocess.run(command)

    if result.returncode == 0:
        print("ENFORCED: DROP rule added")
    else:
        print("ERROR: iptables command failed")


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--apply",
        action="store_true",
        help="Actually add DROP rules to WALL2",
    )

    args = parser.parse_args()

    print("=" * 60)
    print("RESOLUTE PHASE 5 - SAFE FIREWALL ENFORCER")
    print("=" * 60)

    if args.apply:
        print("MODE: APPLY")
    else:
        print("MODE: DRY RUN")

    print()

    candidates = get_candidates()

    print(f"Block candidates: {len(candidates)}")
    print()

    seen = set()

    for result in candidates:
        source_ip = result["source_ip"]

        if source_ip in seen:
            continue

        seen.add(source_ip)

        print(f"Source IP  : {source_ip}")
        print(f"Confidence : {result.get('confidence')}")
        print(f"Decision   : {result.get('decision')}")

        if rule_exists(source_ip):
            print("Status     : RULE ALREADY EXISTS")
        else:
            block(source_ip, args.apply)

        print()


if __name__ == "__main__":
    main()
