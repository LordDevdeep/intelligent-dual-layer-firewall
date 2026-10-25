from cicflowmeter.flow import Flow
from cicflowmeter.features.context import PacketDirection
from scapy.all import IP, TCP

# Create a tiny synthetic TCP flow
p1 = IP(src="10.10.10.2", dst="10.10.10.1") / TCP(
    sport=12345, dport=80, flags="S", window=64240
)
p2 = IP(src="10.10.10.1", dst="10.10.10.2") / TCP(
    sport=80, dport=12345, flags="SA", window=64240
)

flow = Flow(p1, PacketDirection.FORWARD)
flow.add_packet(p2, PacketDirection.REVERSE)

data = flow.get_data()

print("Generated CICFlowMeter fields:", len(data))
print()
print("Sample fields:")
for key, value in list(data.items())[:10]:
    print(f"  {key}: {value}")

print()
print("CICFlowMeter compatibility test: OK")
