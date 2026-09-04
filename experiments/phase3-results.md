# Resolute — Phase 3 Experimental Results

## 1. Objective

The objective of Phase 3 was to evaluate the prototype Intelligent Dual-Layer Firewall pipeline in an isolated virtual laboratory.

The experiment tested the following workflow:

Detect → Analyse → Validate → Adapt → Defend → Recover

The evaluation focused on ML-based traffic classification, validated threat intelligence, adaptive blocking, temporary rule expiration, and connectivity recovery.

---

## 2. Experimental Environment

- Firewall/Wall 1: Ubuntu Linux VM
- Attacker/Test VM: Kali Linux
- Isolated network: 10.10.10.0/24
- Wall 1 interface: enp0s8
- Wall 1 IP: 10.10.10.1
- Kali test IP: 10.10.10.2
- Firewall technology: iptables
- ML algorithm: Random Forest
- ML features:
  - packets
  - bytes
  - TCP packets
  - UDP packets
  - ICMP packets

All traffic used during testing was restricted to the isolated laboratory network.

---

## 3. ML Training Result

The initial training dataset contained:

- NORMAL samples: 13
- SUSPICIOUS samples: 13
- Total samples: 26

The dataset was divided into training and testing subsets.

Random Forest evaluation produced:

- Accuracy: 1.00
- NORMAL precision: 1.00
- NORMAL recall: 1.00
- NORMAL F1-score: 1.00
- SUSPICIOUS precision: 1.00
- SUSPICIOUS recall: 1.00
- SUSPICIOUS F1-score: 1.00
- Test samples: 7

The trained model was successfully saved as:

`detection/resolute_model.pkl`

### Interpretation

The result demonstrates that the prototype successfully learned to distinguish the collected NORMAL and SUSPICIOUS traffic samples.

However, the dataset is small and the traffic classes are relatively easy to distinguish. Therefore, the 100% accuracy result should be considered an initial prototype result rather than evidence of generalization to arbitrary real-world traffic.

---

## 4. Live ML Detection

The trained Random Forest model was connected to the live traffic feature collector.

A controlled high-volume ICMP experiment generated traffic from:

`10.10.10.2`

The live detector produced:

- Source IP: 10.10.10.2
- Packets: 50
- Bytes: 4900
- TCP: 0
- UDP: 0
- ICMP: 50
- ML prediction: SUSPICIOUS
- ML confidence: 1.0
- Attack category: Excessive ICMP Activity
- Threat status: PENDING_VALIDATION

This demonstrated successful real-time integration between traffic observation, ML classification, and attack intelligence generation.

---

## 5. Threat Validation

The attack intelligence profile was passed to the validation layer.

The validation criteria included:

- ML prediction must be SUSPICIOUS
- ML confidence must be at least 0.80
- An attack category must be identified
- Traffic volume must meet the validation threshold

The observed suspicious profile satisfied these conditions and was classified as:

`VALIDATED_THREAT`

Only validated intelligence was permitted to trigger the adaptive Wall 2 response.

---

## 6. Adaptive Wall 2 Experiment

Wall 2 used an iptables chain named:

`WALL2`

The chain was connected to the INPUT chain of the protected Ubuntu system.

A validated threat from:

`10.10.10.2`

resulted in a temporary DROP rule.

### Blocking Result

During the active Wall 2 block, Kali executed:

`ping -c 5 10.10.10.1`

Observed result:

- Packets transmitted: 5
- Packets received: 0
- Packet loss: 100%

This demonstrated that the validated threat was successfully blocked by Wall 2.

---

## 7. Automatic Rollback and Recovery

The adaptive defense used a temporary blocking period of 60 seconds.

After the blocking period expired, the DROP rule was automatically removed.

A second connectivity test was performed from Kali:

`ping -c 5 10.10.10.1`

Observed result:

- Packets transmitted: 5
- Packets received: 5
- Packet loss: 0%

This demonstrated successful recovery after automatic rollback.

---

## 8. Overall Experimental Results

| Test | Result |
|---|---|
| ML training accuracy | 100% |
| Training samples | 26 |
| Live suspicious classification | Successful |
| Live ML confidence | 1.0 |
| Threat validation | VALIDATED_THREAT |
| Wall 2 blocking | Successful |
| Packets during block | 0/5 received |
| Packet loss during block | 100% |
| Automatic rollback | Successful |
| Packets after rollback | 5/5 received |
| Packet loss after rollback | 0% |

---

## 9. Key Observation

The prototype successfully demonstrated a feedback-based defensive workflow:

Traffic Detection
→ ML Classification
→ Attack Intelligence
→ Threat Validation
→ Adaptive Wall 2 Response
→ Temporary Blocking
→ Automatic Rollback
→ Connectivity Recovery

The experiment demonstrates the feasibility of using validated ML-derived intelligence to drive adaptive firewall behavior in an isolated laboratory environment.

---

## 10. Limitations

The current prototype has several limitations:

1. The training dataset is small, containing only 26 samples.
2. The current feature set is limited to basic packet and protocol counts.
3. The suspicious traffic scenario primarily represents excessive ICMP activity.
4. The current experiment does not represent the full diversity of real-world attacks.
5. The initial ML accuracy should not be interpreted as proof of generalization.
6. More attack types and normal traffic patterns are required for stronger evaluation.
7. The current adaptive policy uses a fixed temporary blocking duration of 60 seconds.

---

## 11. Future Experimental Work

Future experiments should expand the dataset and evaluate:

- Multiple attack categories
- Different traffic rates
- TCP and UDP suspicious activity
- Different packet sizes
- False-positive rate
- False-negative rate
- Detection latency
- Validation latency
- Blocking latency
- Recovery time
- Static firewall versus adaptive firewall
- Repeated attacks after previous intelligence has been learned

These experiments will provide stronger evidence for evaluating whether feedback-based adaptive defense improves firewall response.
