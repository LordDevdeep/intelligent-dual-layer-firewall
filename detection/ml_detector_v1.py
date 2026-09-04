#!/usr/bin/env python3

from collections import defaultdict
from datetime import datetime

import joblib
from scapy.all import sniff, IP, TCP, UDP, ICMP


MODEL_FILE = "detection/resolute_model.pkl"
MONITORED_IP = "10.10.10.2"

data = defaultdict(lambda: {
    "packets": 0,
    "bytes": 0,
    "tcp": 0,
    "udp": 0,
    "icmp": 0
})


print("Resolute Wall 1 - Live ML Detector")
print("Loading trained model...\n")

model_data = joblib.load(MODEL_FILE)

model = model_data["model"]
encoder = model_data["encoder"]
features = model_data["features"]

print("Model loaded successfully.")
print(f"Monitoring source: {MONITORED_IP}")
print("Monitoring interface: enp0s8")
print("Press Ctrl+C to stop.\n")


def process_packet(packet):

    if IP not in packet:
        return

    source_ip = packet[IP].src

    if source_ip != MONITORED_IP:
        return

    stats = data[source_ip]

    stats["packets"] += 1
    stats["bytes"] += len(packet)

    if TCP in packet:
        stats["tcp"] += 1

    elif UDP in packet:
        stats["udp"] += 1

    elif ICMP in packet:
        stats["icmp"] += 1

    sample = [[
        stats["packets"],
        stats["bytes"],
        stats["tcp"],
        stats["udp"],
        stats["icmp"]
    ]]

    prediction = model.predict(sample)[0]
    label = encoder.inverse_transform([prediction])[0]

    confidence = model.predict_proba(sample)[0].max()

    print(
        f"[ML] {datetime.now()} | "
        f"src={source_ip} | "
        f"packets={stats['packets']} | "
        f"tcp={stats['tcp']} | "
        f"udp={stats['udp']} | "
        f"icmp={stats['icmp']} | "
        f"prediction={label} | "
        f"confidence={confidence:.2f}"
    )


sniff(
    iface="enp0s8",
    filter="ip",
    prn=process_packet,
    store=False
)
