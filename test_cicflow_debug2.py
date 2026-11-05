from scapy.all import sniff, conf, IP, TCP
from cicflowmeter.flow_session import FlowSession
from pathlib import Path
import time

ROOT = Path(__file__).resolve().parent

interface = conf.ifaces.dev_from_index(10)

output = ROOT / "experiments" / "phase5" / "debug2.csv"
output.parent.mkdir(parents=True, exist_ok=True)

session = FlowSession(
    output_mode="csv",
    output=str(output),
    fields=None,
    verbose=False,
)

packets = 0

def process_packet(packet):
    global packets

    if IP in packet and TCP in packet:
        packets += 1

        print(
            "PACKET",
            packet[IP].src,
            "->",
            packet[IP].dst,
            "Flags:",
            packet[TCP].flags
        )

        session.process(packet)


print("Starting capture...")
print("Generate Kali HTTP traffic now.")

sniff(
    iface=interface,
    filter="tcp and host 192.168.56.101",
    timeout=30,
    prn=process_packet,
    store=False,
)

print("\nPackets received:", packets)

print("Flows before flush:", len(list(session.get_flows())))

print("\nFlushing session...")

session.flush_flows()

print("Flows after flush:", len(list(session.get_flows())))

print("\nCSV exists:", output.exists())

if output.exists():
    print("CSV size:", output.stat().st_size)

    with output.open("r", encoding="utf-8", errors="replace") as f:
        print("\nCSV contents:")
        print(f.read()[:3000])

print("\nDiagnostic finished.")