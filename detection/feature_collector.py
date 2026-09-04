#!/usr/bin/env python3

from datetime import datetime
from collections import defaultdict
from scapy.all import sniff, IP, TCP, UDP, ICMP


packet_stats = defaultdict(lambda: {
    "packets": 0,
    "bytes": 0,
    "tcp": 0,
    "udp": 0,
    "icmp": 0,
    "first_seen": None,
    "last_seen": None
})


def process_packet(packet):

    if IP not in packet:
        return

    source_ip = packet[IP].src
    timestamp = datetime.now()

    stats = packet_stats[source_ip]

    stats["packets"] += 1
    stats["bytes"] += len(packet)

    if stats["first_seen"] is None:
        stats["first_seen"] = timestamp

    stats["last_seen"] = timestamp

    if TCP in packet:
        stats["tcp"] += 1

    elif UDP in packet:
        stats["udp"] += 1

    elif ICMP in packet:
        stats["icmp"] += 1

    print(
        f"[FEATURE] {timestamp} | "
        f"src={source_ip} | "
        f"packets={stats['packets']} | "
        f"bytes={stats['bytes']} | "
        f"tcp={stats['tcp']} | "
        f"udp={stats['udp']} | "
        f"icmp={stats['icmp']}"
    )


print("Resolute Wall 1 - Traffic Feature Collector")
print("Monitoring enp0s8...")
print("Press Ctrl+C to stop.\n")


sniff(
    iface="enp0s8",
    filter="ip",
    prn=process_packet,
    store=False
)
