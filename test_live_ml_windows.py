import sys
import json
import joblib
import time

from pathlib import Path
from datetime import datetime

from scapy.all import sniff, conf
from cicflowmeter.flow_session import FlowSession


# ============================================================
# 1. PROJECT CONFIGURATION
# ============================================================

ROOT = Path(__file__).resolve().parent

SRC = ROOT / "src"
MODEL_PATH = ROOT / "models" / "resolute_random_forest.joblib"

EXPERIMENT_DIR = ROOT / "experiments" / "phase5"
LIVE_TEST_DIR = EXPERIMENT_DIR / "live_test"

ML_LOG = LIVE_TEST_DIR / "ml_detection_log.jsonl"
CSV_OUTPUT = EXPERIMENT_DIR / "windows_live_ml.csv"

KALI_IP = "192.168.56.101"
WINDOWS_IP = "192.168.56.1"

INTERFACE_INDEX = 10
CAPTURE_DURATION = 60


# ============================================================
# 2. IMPORT FEATURE ADAPTER
# ============================================================

sys.path.insert(0, str(SRC))

from cic_feature_adapter import adapt_cicflow_features


# ============================================================
# 3. INITIALIZATION
# ============================================================

def main():

    print("=" * 65)
    print("RESOLUTE - WINDOWS LIVE ML DETECTION")
    print("MODE: DRY RUN - NO FIREWALL ACTION")
    print("=" * 65)

    LIVE_TEST_DIR.mkdir(parents=True, exist_ok=True)
    EXPERIMENT_DIR.mkdir(parents=True, exist_ok=True)

    if not MODEL_PATH.exists():
        print("ERROR: Random Forest model not found:")
        print(MODEL_PATH)
        return

    if not SRC.exists():
        print("ERROR: Source directory not found.")
        return

    # Load trained model
    model = joblib.load(MODEL_PATH)

    print("\nRandom Forest loaded successfully.")
    print("Expected features:", len(model.feature_names_in_))

    # Select VirtualBox Host-Only interface
    try:
        interface = conf.ifaces.dev_from_index(INTERFACE_INDEX)
    except Exception as error:
        print("ERROR: Could not find capture interface:", error)
        return

    print("Interface:", interface)

    # Initialize CICFlowMeter
    try:
        session = FlowSession(
            output_mode="csv",
            output=str(CSV_OUTPUT),
            fields=None,
            verbose=False
        )

    except Exception as error:
        print("ERROR initializing CICFlowMeter:", error)
        return

    print("CICFlowMeter initialized successfully.")

    # Start a fresh ML detection log
    ML_LOG.write_text("", encoding="utf-8")

    print("Fresh ML detection log created.")

    #     # ========================================================
    # 4. PACKET CAPTURE
    # ========================================================

    packet_count = 0
    kali_packet_count = 0

    def process_packet(packet):

        nonlocal packet_count, kali_packet_count

        packet_count += 1

        if packet.haslayer("IP"):
            if packet["IP"].src == KALI_IP or packet["IP"].dst == KALI_IP:
                kali_packet_count += 1

        try:
            session.process(packet)
        except Exception as error:
            print("Packet processing error:", error)

        if packet_count % 25 == 0:
            print(
                f"Packets received: {packet_count} | "
                f"Kali-related: {kali_packet_count}"
            )

    print("\n" + "=" * 65)
    print("LIVE PACKET CAPTURE STARTED")
    print("Interface:", interface)
    print("Kali IP:", KALI_IP)
    print("Windows IP:", WINDOWS_IP)
    print("Duration:", CAPTURE_DURATION, "seconds")
    print("=" * 65)

    print("\nNOW start the Nmap scan from Kali.")

    try:
        sniff(
            iface=interface,
            filter="tcp",
            timeout=CAPTURE_DURATION,
            prn=process_packet,
            store=False
        )

    except Exception as error:
        print("Packet capture failed:", error)
        return

    print("\nPacket capture finished.")
    print("Total packets:", packet_count)
    print("Kali-related packets:", kali_packet_count)

    # 5. RETRIEVE FLOWS BEFORE FLUSHING
    # IMPORTANT: get_flows() MUST BE CALLED BEFORE flush_flows()
    # ========================================================

    print("\nRetrieving CICFlowMeter flows...")

    try:
        flows = list(session.get_flows())
    except Exception as error:
        print("ERROR retrieving flows:", error)
        flows = []

    print("Completed flows:", len(flows))

    # ========================================================
    # 6. MACHINE LEARNING CLASSIFICATION
    # ========================================================

    benign_count = 0
    attack_count = 0
    error_count = 0

    for number, flow in enumerate(flows, start=1):

        try:

            data = flow.get_data()

            features = adapt_cicflow_features(data)

            if features.shape[1] != len(model.feature_names_in_):
                raise ValueError(
                    f"Expected 78 features, received {features.shape[1]}"
                )

            prediction = int(model.predict(features)[0])

            probabilities = model.predict_proba(features)[0]

            classes = list(model.classes_)

            if prediction not in classes:
                raise ValueError("Prediction not found in model classes.")

            predicted_index = classes.index(prediction)

            confidence = float(probabilities[predicted_index])

            probability_benign = float(
                probabilities[classes.index(0)]
            )

            probability_attack = float(
                probabilities[classes.index(1)]
            )

            label = "ATTACK" if prediction == 1 else "BENIGN"

            if prediction == 1:
                attack_count += 1
            else:
                benign_count += 1

            result = {
                "timestamp": datetime.now().isoformat(),
                "source_ip": data.get("src_ip"),
                "source_port": data.get("src_port"),
                "destination_ip": data.get("dst_ip"),
                "destination_port": data.get("dst_port"),
                "protocol": data.get("protocol"),
                "prediction": prediction,
                "label": label,
                "confidence": confidence,
                "probability_benign": probability_benign,
                "probability_attack": probability_attack,
                "feature_count": int(features.shape[1])
            }

            with ML_LOG.open("a", encoding="utf-8") as log_file:
                log_file.write(json.dumps(result) + "\n")

            print("\n" + "-" * 60)
            print("FLOW:", number)
            print(
                f"{data.get('src_ip')}:{data.get('src_port')} -> "
                f"{data.get('dst_ip')}:{data.get('dst_port')}"
            )
            print("Protocol:", data.get("protocol"))
            print("Feature count:", features.shape[1])
            print("Prediction:", label)
            print("Confidence:", round(confidence, 4))
            print("Probability BENIGN:", round(probability_benign, 4))
            print("Probability ATTACK:", round(probability_attack, 4))
            print("ML log updated successfully.")

        except Exception as error:

            error_count += 1

            print("\nFlow:", number)
            print("Detection error:", error)

    # ========================================================
    # 7. FLUSH CICFLOWMETER SESSION
    # ========================================================

    print("\nFlushing CICFlowMeter session...")

    try:
        session.flush_flows()
        print("CICFlowMeter session flushed successfully.")

    except Exception as error:
        print("Flush warning:", error)

    # ========================================================
    # 8. FINAL SUMMARY
    # ========================================================

    total_flows = len(flows)

    print("\n" + "=" * 65)
    print("RESOLUTE LIVE ML DETECTION COMPLETED")
    print("=" * 65)

    print("Packets captured       :", packet_count)
    print("Total flows retrieved  :", total_flows)
    print("BENIGN predictions     :", benign_count)
    print("ATTACK predictions     :", attack_count)
    print("Detection errors       :", error_count)

    print("\nML Detection Log:")
    print(ML_LOG)

    print("\nCSV Output:")
    print(CSV_OUTPUT)

    print("\nFirewall action: NONE")
    print("=" * 65)


# ============================================================
# 9. PROGRAM ENTRY POINT
# ============================================================

if __name__ == "__main__":
    main()