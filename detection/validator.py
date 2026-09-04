#!/usr/bin/env python3

import json
from datetime import datetime


INTELLIGENCE_FILE = "detection/attack_intelligence.json"
VALIDATED_FILE = "detection/validated_intelligence.json"

MIN_CONFIDENCE = 0.80
MIN_PACKETS = 20


def validate_threat(profile):

    prediction = profile["ml_prediction"]
    confidence = profile["ml_confidence"]
    category = profile["attack_category"]
    packets = profile["traffic"]["packets"]

    reasons = []

    if prediction != "SUSPICIOUS":
        reasons.append("ML prediction is not suspicious")

    if confidence < MIN_CONFIDENCE:
        reasons.append("ML confidence below threshold")

    if category == "None":
        reasons.append("No attack category identified")

    if packets < MIN_PACKETS:
        reasons.append("Traffic volume below validation threshold")

    if not reasons:

        profile["threat_status"] = "VALIDATED_THREAT"
        profile["validation"] = {
            "validated": True,
            "validated_at": datetime.now().isoformat(),
            "reason": "All validation criteria satisfied"
        }

        with open(VALIDATED_FILE, "w") as file:
            json.dump(profile, file, indent=4)

        return True, profile

    profile["threat_status"] = "REJECTED"
    profile["validation"] = {
        "validated": False,
        "validated_at": datetime.now().isoformat(),
        "reason": reasons
    }

    return False, profile


def main():

    print("Resolute - Threat Validation Layer\n")

    try:
        with open(INTELLIGENCE_FILE, "r") as file:
            profile = json.load(file)
    except FileNotFoundError:
        print("No attack intelligence file found.")
        return

    validated, result = validate_threat(profile)

    print(json.dumps(result, indent=4))

    if validated:
        print("\n[VALIDATION] Threat VALIDATED.")
        print("[VALIDATION] Wall 2 may use this intelligence.")
    else:
        print("\n[VALIDATION] Threat REJECTED.")
        print("[VALIDATION] Wall 2 must NOT react.")


if __name__ == "__main__":
    main()
