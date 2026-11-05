import json
from pathlib import Path


# ============================================================
# RESOLUTE - WINDOWS DECISION ENGINE
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parent.parent

LIVE_DIR = PROJECT_ROOT / "experiments" / "phase5" / "live_test"

INPUT_LOG = LIVE_DIR / "ml_detection_log.jsonl"

OUTPUT_LOG = LIVE_DIR / "decision_log.jsonl"

CONFIDENCE_THRESHOLD = 0.80


# ============================================================
# DECISION LOGIC
# ============================================================

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


# ============================================================
# MAIN FUNCTION
# ============================================================

def main():

    print("=" * 60)
    print("RESOLUTE - WINDOWS DECISION ENGINE")
    print("=" * 60)

    # Check input log

    if not INPUT_LOG.exists():

        print(f"Input log not found: {INPUT_LOG}")
        return

    # Create output directory

    OUTPUT_LOG.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    total = 0

    counts = {
        "ALLOW": 0,
        "MONITOR": 0,
        "BLOCK_CANDIDATE": 0,
        "ERROR": 0
    }

    # Process ML detection records

    with INPUT_LOG.open("r", encoding="utf-8") as source, \
         OUTPUT_LOG.open("w", encoding="utf-8") as output:

        for line_number, line in enumerate(source, 1):

            line = line.strip()

            if not line:
                continue

            try:

                result = json.loads(line)

                decision, reason = make_decision(result)

                decision_result = {
                    **result,
                    "decision": decision,
                    "decision_reason": reason
                }

                output.write(
                    json.dumps(decision_result) + "\n"
                )

                total += 1
                counts[decision] += 1

                print(
                    f"{result['source_ip']}:{result['source_port']} "
                    f"-> "
                    f"{result['destination_ip']}:"
                    f"{result['destination_port']}"
                )

                print(f"  ML         : {result['label']}")
                print(f"  Confidence : {result['confidence']:.4f}")
                print(f"  Decision   : {decision}")
                print(f"  Reason     : {reason}")
                print()

            except Exception as error:

                counts["ERROR"] += 1

                print(
                    f"Error processing line {line_number}: {error}"
                )

    # Final summary

    print("=" * 60)
    print("RESOLUTE DECISION ENGINE COMPLETED")
    print("=" * 60)

    print(f"Total flows      : {total}")
    print(f"ALLOW            : {counts['ALLOW']}")
    print(f"MONITOR          : {counts['MONITOR']}")
    print(f"BLOCK_CANDIDATE  : {counts['BLOCK_CANDIDATE']}")
    print(f"ERROR            : {counts['ERROR']}")

    print(f"\nOutput: {OUTPUT_LOG}")

    print("=" * 60)


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":
    main()