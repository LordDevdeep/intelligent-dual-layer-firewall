import time
from cicflowmeter.flow_session import FlowSession
from cicflowmeter.flow import Flow
from scapy.all import AsyncSniffer

INTERFACE = "enp0s3"

print(f"Starting live capture on {INTERFACE}...")
print("Capture for 20 seconds, then stop automatically.")

session = FlowSession(
    output_mode="csv",
    output="/home/lorddevdeep/resolute/experiments/phase5/live_test/live_flows.csv",
    fields=None,
    verbose=False,
)

sniffer = AsyncSniffer(
    iface=INTERFACE,
    filter="ip and (tcp or udp)",
    prn=session.process,
    store=False,
)

sniffer.start()

try:
    time.sleep(20)
finally:
    sniffer.stop()
    session.flush_flows()

print("Live capture finished.")
print("Output: ~/resolute/experiments/phase5/live_test/live_flows.csv")
