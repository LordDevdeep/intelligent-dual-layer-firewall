# Resolute - Phase 4 Experimental Results

## 1. Dataset

The Phase 4 controlled laboratory dataset contains:

- 40 observations
- 31 NORMAL observations
- 9 SUSPICIOUS observations
- 18 recorded columns
- 12 ML features used for classification

The dataset was collected in an isolated laboratory network using controlled normal and suspicious traffic scenarios.

The dataset is intended for research and prototype evaluation. Its small size limits claims about real-world generalization.

---

## 2. Machine Learning Evaluation

A Random Forest classifier with 200 trees and balanced class weighting was evaluated using:

- 75/25 stratified hold-out split
- 5-fold stratified cross-validation

### Hold-out test

Confusion matrix:

| Actual / Predicted | NORMAL | SUSPICIOUS |
|---|---:|---:|
| NORMAL | 8 | 0 |
| SUSPICIOUS | 1 | 1 |

Therefore:

- True Negatives: 8
- False Positives: 0
- False Negatives: 1
- True Positives: 1

Security metrics:

- Precision: 1.0000
- Recall: 0.5000
- F1: 0.6667
- False Positive Rate: 0.0000
- False Negative Rate: 0.5000

Overall hold-out accuracy:

- 90%

The suspicious-class recall is affected strongly by the small test set, which contained only two suspicious observations.

### Cross-validation

Mean F1-macro:

- 0.8447

Standard deviation:

- 0.2227

The relatively high standard deviation indicates variability between folds and reinforces the limitation caused by the small dataset.

---

## 3. Feature Importance

The Random Forest identified the following feature importance values:

| Feature | Importance |
|---|---:|
| unique_dst_ports | 0.2210 |
| packets | 0.1422 |
| bytes | 0.1224 |
| byte_rate | 0.1222 |
| packet_rate | 0.1202 |
| avg_packet_size | 0.0935 |
| syn_count | 0.0627 |
| tcp_ratio | 0.0454 |
| udp_ratio | 0.0445 |
| icmp_ratio | 0.0233 |
| unique_dst_ips | 0.0027 |
| rst_count | 0.0000 |

Destination-port diversity was the strongest feature in this controlled dataset.

---

## 4. Error Analysis

The hold-out test produced:

- 0 false positives
- 1 false negative

The false negative was a SUSPICIOUS TCP SYN scanning observation containing:

- 46 packets
- 2,760 bytes
- 4.6 packets/second
- 46 unique destination ports
- 46 SYN packets
- TCP ratio = 1.0

This demonstrates that even traffic containing strong scanning characteristics can be misclassified by the current model.

Because the test set is small, this result should be treated as an observed limitation rather than a general estimate of real-world detection failure.

---

## 5. Static Firewall Baseline

A conventional static firewall rule was manually inserted:

`DROP traffic from 10.10.10.2`

The Kali host attempted ICMP communication with Ubuntu.

Result:

- 4 packets transmitted
- 100% packet loss

The static rule therefore successfully blocked the tested traffic.

The rule required explicit manual removal to restore connectivity.

---

## 6. Resolute Adaptive Firewall

The existing Resolute adaptive defense mechanism was tested using the validated threat profile.

Threat profile:

- Source IP: 10.10.10.2
- ML prediction: SUSPICIOUS
- ML confidence: 1.0
- Threat status: VALIDATED_THREAT
- Validation: true

The adaptive defense:

1. Read the validated threat intelligence.
2. Created/used the WALL2 chain.
3. Added a DROP rule for the source IP.
4. Maintained the block for 60 seconds.
5. Automatically removed the DROP rule.
6. Restored the firewall state.

The rollback was verified by inspecting the WALL2 chain after the 60-second period.

Post-rollback connectivity from Kali to Ubuntu was restored with 0% packet loss.

---

## 7. Static vs Adaptive Behavior

| Property | Static Firewall | Resolute Adaptive Firewall |
|---|---|---|
| Blocking mechanism | Manual rule | Programmatically applied rule |
| Threat validation | Not part of this baseline | Required before blocking |
| Source-specific response | Yes | Yes |
| Automatic temporary rollback | No | Yes |
| Block duration | Manual/indefinite until removed | 60 seconds in experiment |
| Recovery | Manual | Automatic |
| Tested result | 100% packet loss while blocked | Blocked, then automatically restored |

This experiment demonstrates the operational difference between a manually configured static rule and the tested adaptive response mechanism.

---

## 8. Limitations

The Phase 4 evaluation has important limitations:

1. The dataset contains only 40 observations.
2. Only 9 observations belong to the SUSPICIOUS class.
3. The hold-out test contains only two suspicious observations.
4. Cross-validation variance is relatively high.
5. Suspicious traffic is represented by a limited set of controlled laboratory scenarios.
6. The results should not be interpreted as production-scale detection performance.
7. Further evaluation with larger and more diverse datasets is required.

---

## 9. Phase 4 Conclusion

Phase 4 demonstrated that Resolute can combine behavioral network features, machine-learning classification, threat validation, and adaptive firewall enforcement in an isolated laboratory environment.

The experiments also identified a concrete ML limitation through a false-negative observation.

The adaptive firewall experiment demonstrated automatic source-specific blocking followed by automatic rollback and recovery.

These results provide the experimental foundation for further dataset expansion, robustness testing, and comparison with additional baseline detection approaches.
