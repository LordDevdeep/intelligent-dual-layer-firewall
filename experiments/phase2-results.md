# Resolute Phase 2 Experimental Results

## Environment

- Firewall OS: Ubuntu Linux
- Test client: Kali Linux
- Firewall test interface: enp0s8
- Test client IP: 10.10.10.2
- Firewall test IP: 10.10.10.1
- Detection method: Scapy packet capture
- Detection threshold: 10 ICMP packets

## Experiment 1 — Normal Traffic

Test:
- Kali pinged 8.8.8.8 with 5 ICMP packets.

Result:
- 5 packets transmitted
- 5 packets received
- 0% packet loss
- Normal traffic remained allowed.

Conclusion:
- Wall 1 successfully permitted normal forwarded traffic.

## Experiment 2 — Excessive ICMP Detection

Test:
- Kali generated 15 ICMP packets toward 8.8.8.8.

Result:
- Wall 2 detected ICMP traffic from 10.10.10.2.
- Alert triggered at packet 10.
- Wall 2 automatically inserted a DROP rule into Wall 1.
- Wall 1 recorded blocked packets from 10.10.10.2.

Conclusion:
- Wall 2 successfully detected excessive ICMP activity and triggered an automated defensive response.

## Experiment 3 — Automatic Blocking Verification

Test:
- After the dynamic DROP rule was installed, Kali attempted to reach 8.8.8.8.

Result:
- 100% packet loss was observed.

Conclusion:
- The dynamically inserted Wall 1 rule successfully blocked traffic from the detected source.

## Overall Result

The Resolute prototype demonstrated:

1. Stateful firewall filtering through Wall 1.
2. Live packet monitoring through Wall 2.
3. Threshold-based suspicious traffic detection.
4. Automatic generation of a security alert.
5. Dynamic modification of Wall 1 rules.
6. Successful blocking of the detected source.

## Limitations

- Current detection focuses on ICMP traffic.
- The threshold is manually configured.
- The prototype currently monitors a defined test client.
- Detection is based on packet count rather than a learned behavioral model.
- Further experiments are required for TCP, UDP, scanning, and mixed traffic.
