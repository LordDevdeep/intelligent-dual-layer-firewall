#!/usr/bin/env python3

from collections import defaultdict
from datetime import datetime
from scapy.all import sniff, IP, ICMP

TEST_CLIENT_IP = "10.10.10.2"
THRESHOLD = 10

packet_count = defaultdict(int)


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
                f"Possible excessive ICMP activity from {source_ip} | "
                f"Packets: {count}"
            )


print("Resolute Wall 2 - Live Detection Engine")
print("Monitoring enp0s8...")
print(f"Monitoring client: {TEST_CLIENT_IP}")
print("Press Ctrl+C to stop.\n")

sniff(
    iface="enp0s8",
    filter="icmp",
    prn=process_packet,
    store=False
)#!/usr/bin/env python3

from collections import defaultdict
from datetime import datetime
from scapy.all import sniff, IP, ICMP

packet_count = defaultdict(int)

THRESHOLD = 10


def process_packet(packet):
    if IP in packet and ICMP in packet:
        source_ip = packet[IP].src
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
                f"Possible excessive ICMP activity from {source_ip} | "
                f"Packets: {count}"
            )


print("Resolute Wall 2 - Live Detection Engine")
print("Monitoring enp0s8...")
print("Press Ctrl+C to stop.\n")

sniff(
    iface="enp0s8",
    filter="icmp",
    prn=process_packet,
    store=False
)
