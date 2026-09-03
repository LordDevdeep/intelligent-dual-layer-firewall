# System Architecture

## Project

Intelligent Dual-Layer Firewall

## Core Architecture

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

## Components

### Wall 1
The first defensive layer detects suspicious network traffic and
learns characteristics of observed attacks.

### Honeypot
An isolated deception environment used to safely observe suspicious
activity and collect behavioural information.

### Attack Intelligence Engine
Combines information from Wall 1 and the honeypot to generate and
validate attack intelligence.

### Wall 2
The second defensive layer uses validated intelligence to adapt its
defensive policies.

### Protected Service
A controlled service used to evaluate whether the adaptive defense
improves protection.

## Core Learning Cycle

Detect → Deceive → Observe → Validate → Adapt → Defend → Learn
