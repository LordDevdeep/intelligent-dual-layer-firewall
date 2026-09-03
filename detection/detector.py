#!/usr/bin/env python3

from collections import defaultdict
from datetime import datetime

# Track connection attempts by source IP
connection_attempts = defaultdict(int)

THRESHOLD = 10


def process_event(source_ip):
    connection_attempts[source_ip] += 1

    count = connection_attempts[source_ip]

    if count >= THRESHOLD:
        print(
            f"[ALERT] {datetime.now()} | "
            f"Possible scanning activity from {source_ip} | "
            f"Attempts: {count}"
        )
    else:
        print(
            f"[INFO] {datetime.now()} | "
            f"Traffic from {source_ip} | "
            f"Attempts: {count}"
        )


def main():
    print("Resolute Wall 2 Detection Engine")
    print("Monitoring started...\n")

    while True:
        source_ip = input("Source IP (or 'quit'): ").strip()

        if source_ip.lower() == "quit":
            break

        process_event(source_ip)


if __name__ == "__main__":
    main()
