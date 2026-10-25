# RESOLUTE
## An Intelligent Dual-Layer Firewall for Network Threat Detection and Automated Response

RESOLUTE is an educational cybersecurity research prototype exploring
machine-learning-based network traffic classification and adaptive
firewall enforcement.

The project investigates how traffic classification, decision logic,
and controlled firewall enforcement can work together in a layered
network defense architecture.

## 1. Project Objectives

- Classify network traffic as BENIGN or ATTACK using machine learning.
- Extract network-flow features using CICFlowMeter-compatible tooling.
- Convert model predictions into ALLOW, MONITOR, or BLOCK_CANDIDATE
  decisions.
- Validate the connection between the decision engine and firewall
  enforcement component.
- Evaluate the trained model using a held-out CIC-IDS2017 test dataset.
- Investigate how a dual-layer firewall architecture could use validated
  attack intelligence to support adaptive defense.

## 2. Proposed Architecture

Network Traffic
       |
       v
Wall 1: Traffic Observation and ML Classification
       |
       v
Decision Engine
       |
       v
Attack Intelligence and Validation
       |
       v
Wall 2: Firewall Enforcement
       |
       v
Protected Network Services

The architecture represents the project's intended design. The
components verified so far include ML-based traffic classification,
decision logging, and controlled firewall-enforcer testing.
A complete operational honeypot-to-intelligence-to-adaptive-defense
pipeline has not yet been demonstrated.

## 3. Machine-Learning Model

The project uses a Random Forest classifier trained for binary
network-traffic classification.

Model file:
models/resolute_random_forest.joblib

Dataset:
CIC-IDS2017

Prepared test dataset:
datasets/cicids2017/ml/splits/test.parquet

The evaluation script is:
src/evaluate_model.py

The model evaluation used 29,999 test samples and 78 input features.

### Reported Test Results

| Metric | Result |
|---|---:|
| Accuracy | 99.80% |
| Precision | 99.90% |
| Recall | 99.69% |
| F1-score | 99.80% |
| ROC-AUC | 1.0000 |

### Confusion Matrix

Rows represent actual classes and columns represent predicted classes.

| Actual Class | Predicted BENIGN | Predicted ATTACK |
|---|---:|---:|
| BENIGN | 14,985 | 15 |
| ATTACK | 46 | 14,953 |

These results describe performance on the prepared test dataset.
They do not guarantee equivalent performance on live traffic or
different network environments.

## 4. Traffic Detection and Feature Adaptation

The live detection and feature-adaptation components include:

- src/phase5_live_detector.py
- src/cic_feature_adapter.py
- src/test_cic_feature_compatibility.py

The live detector captures traffic and produces model predictions.
The feature adapter maps CICFlowMeter-compatible flow fields to the
feature structure expected by the trained model.

The feature compatibility test completed successfully and reported
82 generated CICFlowMeter fields.

Live testing has produced a benign prediction. A controlled, end-to-end
live attack-detection result has not yet been established.

## 5. Decision Engine

Script:
src/phase5_decision_engine.py

Input:
experiments/phase5/live_test/ml_detection_log.jsonl

Output:
experiments/phase5/live_test/decision_log.jsonl

The decision engine applies the following logic:

- ALLOW: The model predicts BENIGN.
- MONITOR: The model predicts ATTACK but confidence is below 0.80.
- BLOCK_CANDIDATE: The model predicts ATTACK with confidence of at
  least 0.80.

These decisions are model outputs and should not be treated as
independent proof that traffic is malicious.

## 6. Phase 6 Firewall Enforcement

Script:
src/phase6_firewall_enforcer_test.py

Firewall chain:
WALL2

The Phase 6 enforcer reads the Phase 5 decision log, validates source
IP addresses, identifies BLOCK_CANDIDATE records, and prepares
iptables DROP commands.

The default mode is DRY RUN. In this mode, proposed commands are
displayed but not executed.

Verified tests:

- Phase 5 decision engine processed a live detection record.
- Phase 6 read the connected decision log.
- A benign decision produced zero block candidates.
- A controlled test record for 192.0.2.10 was recognized as one
  BLOCK_CANDIDATE.
- The corresponding firewall command was displayed in dry-run mode.
- The controlled test did not add a firewall rule.
- The original decision log was restored after the test.

The controlled attack-candidate test used prepared test data. It did
not establish that the ML model detected a newly generated attack.

## 7. Verification Performed

- CICFlowMeter feature compatibility test: passed.
- Python syntax compilation for src/: passed.
- Random Forest evaluation on the prepared test dataset: completed.
- Phase 5 decision engine execution: completed.
- Phase 6 decision-log integration: verified.
- Benign-flow dry-run test: passed.
- Controlled BLOCK_CANDIDATE dry-run test: passed.
- Verification that the controlled test rule was absent: passed.

## 8. Technology Stack

- Linux and Ubuntu virtual machine
- Python
- Scikit-learn
- Pandas
- Joblib
- CICFlowMeter-compatible flow processing
- Scapy
- iptables
- CIC-IDS2017 dataset

## 9. Safety

This project is intended for educational and research purposes.

Testing should be conducted only in an authorized, isolated laboratory.
Firewall enforcement can interrupt network connectivity. Keep
enforcement in dry-run mode until end-to-end detection, decision logic,
source-address validation, and rollback procedures have been
thoroughly tested.

Do not remove or overwrite existing firewall rules without verifying
their purpose and having a recovery plan.

## 10. Current Project Status

### Verified Components

- Random Forest evaluation on the prepared CIC-IDS2017 test dataset
  completed successfully.
- Test dataset: 29,999 samples and 78 model input features.
- Reported accuracy: 99.80%.
- Reported precision: 99.90%.
- Reported recall: 99.69%.
- Reported F1-score: 99.80%.
- Reported ROC-AUC: 1.0000.
- Live capture processed five HTTP flows from Kali in the Ubuntu lab.
- The observed live flows were classified as BENIGN and converted into
  ALLOW decisions.
- The Phase 5 decision engine produced the connected decision log.
- The Phase 6 enforcer read the decision log and returned zero block
  candidates for the observed benign decisions.
- A controlled BLOCK_CANDIDATE fixture was recognized in dry-run mode.
- The proposed firewall command was displayed without applying a rule
  during the controlled dry-run test.
- A controlled DROP rule for the reserved test address 192.0.2.10 was
  manually added to WALL2, verified, removed, and verified absent.
- WALL1 exists and is connected to FORWARD.
- WALL2 exists and is connected to INPUT.
- Python syntax compilation for the src and detection directories passed.

### Known Limitations and Remaining Work

- The reported model metrics describe the prepared test dataset;
  equivalent performance on live traffic has not been established.
- The observed live flows were benign. Controlled live attack detection
  has not been verified end to end.
- The controlled firewall-rule test verifies rule insertion and cleanup;
  it does not prove that a real attack is correctly detected and
  automatically blocked by the complete pipeline.
- The complete honeypot-to-attack-intelligence-to-adaptive-defense
  workflow has not been demonstrated end to end.
- Persistence across reboot, rollback automation in the integrated
  pipeline, and production suitability have not been established.

RESOLUTE is an educational research prototype, not a production-ready
firewall. Continue using dry-run mode for automated enforcement until
end-to-end detection, decision safeguards, rollback behavior, and
connectivity recovery have been tested in an authorized lab.
