#!/usr/bin/env python3

import csv
import os
from collections import defaultdict
from datetime import datetime

from scapy.all import sniff, IP, TCP, UDP, ICMP


OUTPUT_FILE = "detection/training_data.csv"

traffic = defaultdict(lambda: {
    "packets": 0,
    "bytes": 0,
    "tcp": 0,
    "udp": 0,
    "icmp": 0
})


def process_packet(packet):

    if IP not in packet:
        return

    source_ip = packet[IP].src
    stats = traffic[source_ip]

    stats["packets"] += 1
    stats["bytes"] += len(packet)

    if TCP in packet:
        stats["tcp"] += 1
    elif UDP in packet:
        stats["udp"] += 1
    elif ICMP in packet:
        stats["icmp"] += 1


def save_observations(label):

    file_exists = os.path.exists(OUTPUT_FILE)

    with open(OUTPUT_FILE, "a", newline="") as file:

        writer = csv.writer(file)

        if not file_exists:
            writer.writerow([
                "timestamp",
                "source_ip",
                "packets",
                "bytes",
                "tcp",
                "udp",
                "icmp",
                "label"
            ])

        for source_ip, stats in traffic.items():

            writer.writerow([
                datetime.now(),
                source_ip,
                stats["packets"],
                stats["bytes"],
                stats["tcp"],
                stats["udp"],
                stats["icmp"],
                label
            ])

    print(f"\nSaved {len(traffic)} observations as {label}.")


print("Resolute - Dataset Collector")
print("Monitoring enp0s8")
print()
print("Choose traffic label:")
print("  normal")
print("  suspicious")
print()

label = input("Label: ").strip().upper()

if label not in ["NORMAL", "SUSPICIOUS"]:
    print("Invalid label. Use normal or suspicious.")
    raise SystemExit(1)

print(f"\nCollecting {label} traffic...")
print("Generate traffic from Kali.")
print("Press Ctrl+C when the experiment is complete.\n")


try:

    sniff(
        iface="enp0s8",
        filter="ip",
        prn=process_packet,
        store=False
    )

except KeyboardInterrupt:

    save_observations(label)

    print("Dataset collection stopped.")
