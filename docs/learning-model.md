# Learning Model

## Overview

The Intelligent Dual-Layer Firewall uses a staged learning process.

The first firewall observes and classifies suspicious traffic.
The honeypot provides additional behavioural evidence.

This information is combined into attack intelligence and
validated before it is used by the second firewall.

## Wall 1 — Attack Learning

Wall 1 is responsible for:

- Monitoring network traffic.
- Extracting relevant traffic features.
- Classifying traffic using machine learning.
- Identifying suspicious activity.
- Recording characteristics of detected attacks.
- Forwarding selected suspicious activity to the honeypot.

Wall 1 initially learns from labelled training data and later uses
observed attack information to improve the system's knowledge of
attack patterns.

## Honeypot — Behaviour Observation

The honeypot is used as a controlled deception environment.

It records information such as:

- Connection attempts.
- Targeted services.
- Targeted ports.
- Authentication attempts.
- Session information.
- Commands or interactions where applicable.
- Timing and frequency of activity.

The honeypot does not directly modify firewall rules.

## Attack Intelligence

Information from Wall 1 and the honeypot is combined into an
attack profile.

An attack profile may contain:

- Attack category.
- Source information.
- Target service.
- Target port.
- Traffic characteristics.
- Behavioural characteristics.
- Machine-learning confidence.
- Honeypot evidence.
- Threat confidence.

## Intelligence Validation

Attack intelligence must be validated before being used for
adaptive defense.

The validation stage checks whether the available evidence is
sufficiently consistent and reliable.

Only intelligence that satisfies the defined validation criteria
is passed to Wall 2.

## Wall 2 — Adaptive Learning

Wall 2 uses validated attack intelligence to update its defensive
knowledge and policies.

The initial implementation will focus on adaptive defensive
policies rather than automatic retraining of the machine-learning
model.

Wall 2 may use validated intelligence to:

- Block identified malicious traffic.
- Restrict suspicious traffic.
- Apply temporary defensive rules.
- Increase monitoring for known attack patterns.

Adaptive rules should be logged and designed with rollback or
expiration mechanisms.

## Learning Cycle

The overall learning cycle is:

Detect
  ↓
Deceive
  ↓
Observe
  ↓
Analyse
  ↓
Validate
  ↓
Adapt
  ↓
Defend
  ↓
Learn

## Research Objective

The project will evaluate whether this feedback-based learning
process improves the response of the second defensive layer when
similar or related attacks occur again.
