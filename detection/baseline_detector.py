#!/usr/bin/env python3

from collections import defaultdict
from datetime import datetime
from scapy.all import sniff, IP, TCP, UDP, ICMP


THRESHOLD = 20

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

    count = stats["packets"]

    if count >= THRESHOLD:
        print(
            f"[ALERT] {datetime.now()} | "
            f"Possible excessive traffic | "
            f"src={source_ip} | "
            f"packets={count} | "
            f"bytes={stats['bytes']}"
        )
    else:
        print(
            f"[INFO] {datetime.now()} | "
            f"src={source_ip} | "
            f"packets={count} | "
            f"tcp={stats['tcp']} | "
            f"udp={stats['udp']} | "
            f"icmp={stats['icmp']}"
        )


print("Resolute Wall 1 - Baseline Detector")
print(f"Detection threshold: {THRESHOLD} packets")
print("Monitoring enp0s8...")
print("Press Ctrl+C to stop.\n")


sniff(
    iface="enp0s8",
    filter="ip",
    prn=process_packet,
    store=False
)
