#!/usr/bin/env python3

from collections import defaultdict
from datetime import datetime
import subprocess
from scapy.all import sniff, IP, ICMP

TEST_CLIENT_IP = "10.10.10.2"
THRESHOLD = 10

packet_count = defaultdict(int)
blocked_ips = set()


def block_ip(source_ip):
    if source_ip in blocked_ips:
        return

    result = subprocess.run(
        ["iptables", "-C", "WALL1", "-s", source_ip, "-j", "DROP"],
        capture_output=True
    )

    if result.returncode != 0:
        subprocess.run(
            ["iptables", "-I", "WALL1", "1", "-s", source_ip, "-j", "DROP"],
            check=True
        )

    blocked_ips.add(source_ip)

    print(
        f"[BLOCK] {datetime.now()} | "
        f"WALL1 blocked {source_ip}"
    )


def process_packet(packet):
    if IP in packet and ICMP in packet:
        source_ip = packet[IP].src

        if source_ip != TEST_CLIENT_IP:
            return

        packet_count[source_ip] += 1
        count = packet_count[source_ip]

        print(
            f"[INFO] {datetime.now()} | "
            f"ICMP from {source_ip} | "
            f"Packets: {count}"
        )

        if count >= THRESHOLD:
            print(
                f"[ALERT] {datetime.now()} | "
                f"Excessive ICMP activity from {source_ip}"
            )

            block_ip(source_ip)


print("Resolute Wall 2 - Integrated Detection Engine")
print("Monitoring enp0s8...")
print(f"Monitoring client: {TEST_CLIENT_IP}")
print(f"Detection threshold: {THRESHOLD}")
print("Automatic response: WALL1 DROP")
print("Press Ctrl+C to stop.\n")

sniff(
    iface="enp0s8",
    filter="icmp",
    prn=process_packet,
    store=False
)
