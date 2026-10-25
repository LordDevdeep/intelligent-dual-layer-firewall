import json
from pathlib import Path

INPUT_LOG = Path(
    "/home/lorddevdeep/resolute/experiments/phase5/live_test/ml_detection_log.jsonl"
)

OUTPUT_LOG = Path(
    "/home/lorddevdeep/resolute/experiments/phase5/live_test/decision_log.jsonl"
)

CONFIDENCE_THRESHOLD = 0.80


def make_decision(result):
    prediction = int(result["prediction"])
    confidence = float(result["confidence"])

    if prediction == 0:
        decision = "ALLOW"
        reason = "ML classified flow as BENIGN"

    elif confidence < CONFIDENCE_THRESHOLD:
        decision = "MONITOR"
        reason = (
            f"ATTACK prediction but confidence "
            f"{confidence:.4f} < {CONFIDENCE_THRESHOLD:.2f}"
        )

    else:
        decision = "BLOCK_CANDIDATE"
        reason = (
            f"ATTACK prediction with confidence "
            f"{confidence:.4f} >= {CONFIDENCE_THRESHOLD:.2f}"
        )

    return decision, reason


def main():
    if not INPUT_LOG.exists():
        print(f"Input log not found: {INPUT_LOG}")
        return

    total = 0
    counts = {
        "ALLOW": 0,
        "MONITOR": 0,
        "BLOCK_CANDIDATE": 0,
    }

    with INPUT_LOG.open() as source, OUTPUT_LOG.open("w") as output:

        for line in source:
            line = line.strip()

            if not line:
                continue

            result = json.loads(line)

            decision, reason = make_decision(result)

            decision_result = {
                **result,
                "decision": decision,
                "decision_reason": reason,
            }

            output.write(json.dumps(decision_result) + "\n")

            total += 1
            counts[decision] += 1

            print(
                f"{result['source_ip']}:{result['source_port']} -> "
                f"{result['destination_ip']}:{result['destination_port']}"
            )
            print(f"  ML         : {result['label']}")
            print(f"  Confidence : {result['confidence']:.4f}")
            print(f"  Decision   : {decision}")
            print(f"  Reason     : {reason}")
            print()

    print("=" * 60)
    print("RESOLUTE DECISION ENGINE COMPLETE")
    print("=" * 60)
    print(f"Total flows      : {total}")
    print(f"ALLOW            : {counts['ALLOW']}")
    print(f"MONITOR          : {counts['MONITOR']}")
    print(f"BLOCK_CANDIDATE  : {counts['BLOCK_CANDIDATE']}")
    print(f"Output           : {OUTPUT_LOG}")


if __name__ == "__main__":
    main()
