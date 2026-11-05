import json
import time
from datetime import datetime
from pathlib import Path
from collections import defaultdict

from scapy.all import sniff, IP, TCP, conf


# ============================================================
# RESOLUTE - BEHAVIOURAL SYN SCAN DETECTOR
# Windows implementation
# ============================================================

ROOT = Path(__file__).resolve().parent

INTERFACE_INDEX = 10

WINDOWS_IP = "192.168.56.1"
KALI_IP = "192.168.56.101"

CAPTURE_DURATION = 45
SYN_THRESHOLD = 20

LOG_FILE = (
    ROOT
    / "experiments"
    / "phase5"
    / "live_test"
    / "decision_log.jsonl"
)


def main():

    print("=" * 65)
    print("RESOLUTE - BEHAVIOURAL SYN SCAN DETECTOR")
    print("=" * 65)

    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)

    interface = conf.ifaces.dev_from_index(INTERFACE_INDEX)

    print("Interface:", interface)
    print("Windows:", WINDOWS_IP)
    print("Attacker:", KALI_IP)
    print("Capture duration:", CAPTURE_DURATION)
    print("SYN threshold:", SYN_THRESHOLD)

    syn_count = 0
    destination_ports = set()
    packet_count = 0

    def process_packet(packet):

        nonlocal syn_count, packet_count

        if not packet.haslayer(IP):
            return

        if not packet.haslayer(TCP):
            return

        ip = packet[IP]
        tcp = packet[TCP]

        if ip.src != KALI_IP or ip.dst != WINDOWS_IP:
            return

        packet_count += 1

        flags = int(tcp.flags)

        # SYN set, ACK not set
        if (flags & 0x02) and not (flags & 0x10):

            syn_count += 1
            destination_ports.add(int(tcp.dport))

    print("\nCapturing TCP traffic for", CAPTURE_DURATION, "seconds...")
    print("Start the Nmap scan from Kali now.")

    try:

        sniff(
            iface=interface,
            filter="tcp",
            timeout=CAPTURE_DURATION,
            prn=process_packet,
            store=False
        )

    except Exception as error:

        print("\nCapture failed:", error)
        return

    unique_ports = len(destination_ports)

    print("\n" + "=" * 65)
    print("BEHAVIOURAL ANALYSIS RESULTS")
    print("=" * 65)

    print("TCP packets from Kali:", packet_count)
    print("SYN packets:", syn_count)
    print("Unique destination ports:", unique_ports)
    print("Scanned ports:", sorted(destination_ports))

    suspicious = (
        syn_count >= SYN_THRESHOLD
        and unique_ports >= SYN_THRESHOLD
    )

    if suspicious:

        decision = "BLOCK_CANDIDATE"
        reason = "Behavioural detector identified TCP SYN port scanning"

        print("\nWARNING: SUSPICIOUS PORT SCANNING ACTIVITY")

    else:

        decision = "ALLOW"
        reason = "No port scanning threshold exceeded"

        print("\nNo suspicious port scan detected.")

    result = {
        "timestamp": datetime.now().isoformat(),
        "source_ip": KALI_IP,
        "destination_ip": WINDOWS_IP,
        "decision": decision,
        "reason": reason,
        "detection_source": "SYN_BEHAVIOURAL",
        "tcp_packets": packet_count,
        "syn_packets": syn_count,
        "unique_destination_ports": unique_ports,
        "destination_ports": sorted(destination_ports)
    }

    with LOG_FILE.open("a", encoding="utf-8") as file:
        file.write(json.dumps(result) + "\n")

    print("\nDecision:", decision)
    print("Decision log updated:", LOG_FILE)

    print("\n" + "=" * 65)
    print("BEHAVIOURAL DETECTION COMPLETED")
    print("=" * 65)


if __name__ == "__main__":
    main()