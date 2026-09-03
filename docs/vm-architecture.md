# Virtual Machine Architecture

## VM Overview

The prototype uses four virtual machines inside an isolated
VirtualBox laboratory.

| VM | Role | Initial RAM |
|---|---|---:|
| Kali Linux | Controlled attacker | 2 GB |
| Wall 1 | ML detection and attack learning | 2 GB |
| Honeypot | Behaviour observation | 2 GB |
| Wall 2 | Adaptive defense and protected service | 2 GB |

## Traffic Flow

Kali
  ↓
Wall 1
  ↓
Suspicious traffic
  ↓
Honeypot
  ↓
Attack intelligence
  ↓
Validation
  ↓
Wall 2
  ↓
Protected service

## Wall 1

Responsibilities:

- Monitor traffic.
- Apply initial firewall policies.
- Extract traffic features.
- Detect suspicious activity.
- Classify suspicious traffic.
- Record attack characteristics.
- Divert selected suspicious activity to the honeypot.

## Honeypot

Responsibilities:

- Provide a controlled deceptive environment.
- Observe suspicious activity.
- Record attacker behaviour.
- Generate behavioural evidence.

The honeypot does not directly modify firewall policies.

## Wall 2

Responsibilities:

- Receive validated attack intelligence.
- Update defensive policies.
- Apply adaptive rules.
- Protect the test service.
- Record adaptive actions.

## Isolation

All virtual machines will operate inside an isolated virtual
laboratory.

The honeypot and protected service must not be exposed to the
public Internet.

All attack traffic used for experiments will be generated
inside the controlled laboratory.
