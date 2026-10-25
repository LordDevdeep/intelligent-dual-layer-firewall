import ipaddress
import json
import subprocess
from pathlib import Path

DECISION_LOG = Path(
    "/home/lorddevdeep/resolute/experiments/phase5/live_test/decision_log.jsonl"
)

CHAIN = "WALL2"


def valid_ip(value):
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def get_block_candidates():
    candidates = []

    if not DECISION_LOG.exists():
        return candidates

    with DECISION_LOG.open() as f:
        for line in f:
            if not line.strip():
                continue

            result = json.loads(line)

            if result.get("decision") == "BLOCK_CANDIDATE":
                source_ip = result.get("source_ip")

                if source_ip and valid_ip(source_ip):
                    candidates.append({
                        "source_ip": source_ip,
                        "confidence": result.get("confidence"),
                        "destination_ip": result.get("destination_ip"),
                        "destination_port": result.get("destination_port"),
                    })

    return candidates


def firewall_rule_exists(source_ip):
    result = subprocess.run(
        ["sudo", "iptables", "-C", CHAIN, "-s", source_ip, "-j", "DROP"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    return result.returncode == 0


def add_block_rule(source_ip, dry_run=True):
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

    if dry_run:
        print("DRY RUN: rule NOT applied")
        return True

    result = subprocess.run(command)

    return result.returncode == 0


def main():
    candidates = get_block_candidates()

    print("=" * 60)
    print("RESOLUTE PHASE 5 - FIREWALL ENFORCER")
    print("MODE: DRY RUN")
    print("=" * 60)

    print(f"Block candidates: {len(candidates)}")
    print()

    if not candidates:
        print("No BLOCK_CANDIDATE decisions found.")
        return

    seen = set()

    for candidate in candidates:
        source_ip = candidate["source_ip"]

        if source_ip in seen:
            continue

        seen.add(source_ip)

        print(f"Source IP   : {source_ip}")
        print(f"Confidence  : {candidate['confidence']}")
        print(f"Destination : {candidate['destination_ip']}")
        print(f"Port        : {candidate['destination_port']}")

        if firewall_rule_exists(source_ip):
            print("Status      : RULE ALREADY EXISTS")
        else:
            add_block_rule(source_ip, dry_run=True)

        print()


if __name__ == "__main__":
    main()
