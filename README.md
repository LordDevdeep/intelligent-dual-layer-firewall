# Intelligent Dual-Layer Firewall

An adaptive cybersecurity prototype using two firewall layers, a
honeypot-based deception environment, validated attack intelligence,
and adaptive defense.

## Overview

The Intelligent Dual-Layer Firewall is designed as a small,
adaptive cybersecurity system consisting of two defensive firewall
layers and a single isolated honeypot.

The first firewall uses machine learning to identify suspicious
traffic and learns characteristics of observed attacks.

Suspicious activity is observed within the honeypot to collect
additional behavioural information.

This information is converted into structured attack intelligence
and validated before being provided to the second firewall.

The second firewall uses the validated intelligence to adapt its
defensive policies against subsequent similar attacks.

## Architecture

Attacker
    ↓
Wall 1 — ML Detection & Attack Learning
    ↓
Honeypot — Behaviour Observation
    ↓
Attack Intelligence & Validation
    ↓
Wall 2 — Adaptive Defense
    ↓
Protected Service

## Research Question

Can validated attack intelligence learned from suspicious traffic
and honeypot behaviour improve the response of a second defensive
layer against subsequent similar attacks?

## Objectives

- Detect suspicious network traffic using machine learning.
- Learn attack characteristics at the first firewall.
- Observe suspicious activity using an isolated honeypot.
- Generate structured attack intelligence.
- Validate attack intelligence before defensive adaptation.
- Adapt the second firewall using validated intelligence.
- Evaluate whether repeated or similar attacks are handled more
  effectively after adaptation.

## Technology Stack

- VirtualBox
- Linux
- Kali Linux
- nftables
- Cowrie
- Python
- Scikit-learn
- Pandas
- SQLite

## Project Status

Phase 1 — Foundation

## Safety

All experiments are performed inside an isolated virtual
laboratory using controlled test traffic.

This project is intended for educational and research purposes.
