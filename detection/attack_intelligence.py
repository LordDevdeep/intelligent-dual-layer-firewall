#!/usr/bin/env python3

from datetime import datetime
import json


INTELLIGENCE_FILE = "detection/attack_intelligence.json"


def create_attack_profile(
    source_ip,
    packets,
    bytes_count,
    tcp,
    udp,
    icmp,
    prediction,
    confidence
):

    if prediction == "SUSPICIOUS":

        if icmp > 0 and icmp >= tcp and icmp >= udp:
            attack_category = "Excessive ICMP Activity"
        elif tcp > udp and tcp > icmp:
            attack_category = "Suspicious TCP Activity"
        elif udp > tcp and udp > icmp:
            attack_category = "Suspicious UDP Activity"
        else:
            attack_category = "Suspicious Network Activity"

        threat_status = "PENDING_VALIDATION"

    else:

        attack_category = "None"
        threat_status = "NORMAL"


    profile = {
        "timestamp": datetime.now().isoformat(),
        "source_ip": source_ip,
        "traffic": {
            "packets": packets,
            "bytes": bytes_count,
            "tcp": tcp,
            "udp": udp,
            "icmp": icmp
        },
        "ml_prediction": prediction,
        "ml_confidence": round(float(confidence), 3),
        "attack_category": attack_category,
        "threat_status": threat_status
    }

    with open(INTELLIGENCE_FILE, "w") as file:
        json.dump(profile, file, indent=4)

    return profile


if __name__ == "__main__":

    profile = create_attack_profile(
        source_ip="10.10.10.2",
        packets=40,
        bytes_count=3360,
        tcp=0,
        udp=0,
        icmp=40,
        prediction="SUSPICIOUS",
        confidence=0.95
    )

    print("Attack intelligence generated:\n")
    print(json.dumps(profile, indent=4))
