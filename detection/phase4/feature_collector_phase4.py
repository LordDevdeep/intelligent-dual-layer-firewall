#!/usr/bin/env python3

import csv
import os
import time
from collections import defaultdict

from scapy.all import sniff, IP, TCP, UDP, ICMP


OUTPUT_FILE = "detection/phase4/training_data_phase4.csv"
WINDOW_SECONDS = 10
ATTACKER_IP = "10.10.10.2"


traffic = defaultdict(lambda: {
    "packets": 0,
    "bytes": 0,
    "tcp": 0,
    "udp": 0,
    "icmp": 0,
    "dst_ips": set(),
    "dst_ports": set(),
    "syn": 0,
    "rst": 0
})


def process_packet(packet):
    if IP not in packet:
        return

    source_ip = packet[IP].src
    stats = traffic[source_ip]

    stats["packets"] += 1
    stats["bytes"] += len(packet)

    stats["dst_ips"].add(packet[IP].dst)

    if TCP in packet:
        stats["tcp"] += 1

        if packet[TCP].flags & 0x02:
            stats["syn"] += 1

        if packet[TCP].flags & 0x04:
            stats["rst"] += 1

        if packet[TCP].dport:
            stats["dst_ports"].add(packet[TCP].dport)

    elif UDP in packet:
        stats["udp"] += 1

        if packet[UDP].dport:
            stats["dst_ports"].add(packet[UDP].dport)

    elif ICMP in packet:
        stats["icmp"] += 1


def write_header_if_needed():
    file_exists = os.path.exists(OUTPUT_FILE)

    if not file_exists or os.path.getsize(OUTPUT_FILE) == 0:
        with open(OUTPUT_FILE, "w", newline="") as file:
            writer = csv.writer(file)

            writer.writerow([
                "timestamp",
                "source_ip",
                "packets",
                "bytes",
                "tcp",
                "udp",
                "icmp",
                "packet_rate",
                "byte_rate",
                "avg_packet_size",
                "tcp_ratio",
                "udp_ratio",
                "icmp_ratio",
                "unique_dst_ips",
                "unique_dst_ports",
                "syn_count",
                "rst_count",
                "label"
            ])


def save_window(label):
    if not traffic:
        return 0

    write_header_if_needed()

    rows_saved = 0

    with open(OUTPUT_FILE, "a", newline="") as file:
        writer = csv.writer(file)

        for source_ip, stats in traffic.items():

            packets = stats["packets"]
            bytes_total = stats["bytes"]

            packet_rate = packets / WINDOW_SECONDS
            byte_rate = bytes_total / WINDOW_SECONDS

            if packets > 0:
                avg_packet_size = bytes_total / packets
            else:
                avg_packet_size = 0

            tcp_ratio = stats["tcp"] / packets if packets else 0
            udp_ratio = stats["udp"] / packets if packets else 0
            icmp_ratio = stats["icmp"] / packets if packets else 0

            writer.writerow([
                time.strftime("%Y-%m-%d %H:%M:%S"),
                source_ip,
                packets,
                bytes_total,
                stats["tcp"],
                stats["udp"],
                stats["icmp"],
                round(packet_rate, 4),
                round(byte_rate, 4),
                round(avg_packet_size, 4),
                round(tcp_ratio, 4),
                round(udp_ratio, 4),
                round(icmp_ratio, 4),
                len(stats["dst_ips"]),
                len(stats["dst_ports"]),
                stats["syn"],
                stats["rst"],
                label
            ])

            rows_saved += 1

    traffic.clear()

    return rows_saved


def main():

    print("==============================================")
    print("Resolute - Phase 4 Feature Collector")
    print("==============================================")
    print()
    print("Interface: enp0s8")
    print(f"Window: {WINDOW_SECONDS} seconds")
    print()
    print("Choose traffic label:")
    print("  normal")
    print("  suspicious")
    print()

    label = input("Label: ").strip().upper()

    if label not in ["NORMAL", "SUSPICIOUS"]:
        print("Invalid label.")
        print("Use: normal or suspicious")
        return

    write_header_if_needed()

    print()
    print(f"Collecting {label} traffic...")
    print("Each observation window = 10 seconds.")
    print("Generate traffic from Kali.")
    print("Press Ctrl+C to stop.")
    print()

    try:

        while True:

            traffic.clear()

            sniff(
                iface="enp0s8",
                filter=f"ip and src host {ATTACKER_IP}",
                prn=process_packet,
                store=False,
                timeout=WINDOW_SECONDS
            )

            rows = save_window(label)

            print(
                f"[WINDOW] {WINDOW_SECONDS}s | "
                f"Saved observations: {rows} | "
                f"Label: {label}"
            )

    except KeyboardInterrupt:

        print("\nCollection stopped.")

        if traffic:
            rows = save_window(label)
            print(f"Saved final window: {rows} observations.")

        print(f"Dataset: {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
