from scapy.all import sniff, IP, TCP, UDP, conf
from cicflowmeter.flow_session import FlowSession

print("=" * 50)
print("RESOLUTE - WINDOWS CICFLOWMETER TEST")
print("=" * 50)

session = FlowSession(
    output_mode="csv",
    output="experiments/phase5/windows_test_flows.csv",
    fields=None,
    verbose=False,
)

print("Capturing packets for 20 seconds...")

interface = conf.ifaces.dev_from_index(10)

print("Selected interface:", interface)

packets = sniff(
    iface=interface,
    filter="ip and (tcp or udp)",
    timeout=20,
    prn=session.process,
    store=False,
)

print("Packets captured:", len(packets))

flows = list(session.get_flows())

session.flush_flows()

print("Completed flows:", len(flows))

for i, flow in enumerate(flows, 1):
    data = flow.get_data()

    print("\nFlow:", i)
    print("Source:", data.get("src_ip"))
    print("Destination:", data.get("dst_ip"))
    print("Protocol:", data.get("protocol"))
    print("Available features:", len(data))

print("\nCICFlowMeter test completed.")