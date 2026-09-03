# Network Configuration

## Wall 1

The Ubuntu VM is configured as the first firewall layer.

### Network Interfaces

| Interface | Purpose | Configuration |
|---|---|---|
| enp0s3 | Temporary management/Internet access | NAT, DHCP |
| enp0s8 | Isolated attack-side network | 10.10.10.1/24 |

## Isolated Network

The project attack network uses:

    10.10.10.0/24

Wall 1:

    10.10.10.1/24

The isolated network is implemented using a VirtualBox Internal
Network named:

    IDLF-ATTACK

## Routing

The default route currently uses enp0s3 for temporary Internet
access.

The isolated interface enp0s8 has no default gateway.

## Purpose

The isolated interface will eventually connect Wall 1 to the
controlled attacker environment.

The project will use this isolated network for cybersecurity
experiments.

## Safety

The experimental network must remain isolated from the public
Internet.

The honeypot and protected services must not be exposed directly
to the Internet.
