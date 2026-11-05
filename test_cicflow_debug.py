import sys
import json
import joblib

from pathlib import Path
from datetime import datetime

from scapy.all import sniff, conf
from cicflowmeter.flow_session import FlowSession


# ============================================================
# 1. PROJECT CONFIGURATION
# ============================================================

ROOT = Path(__file__).resolve().parent

SRC_DIR = ROOT / "src"
sys.path.insert(0, str(SRC_DIR))

from cic_feature_adapter import adapt_cicflow_features


MODEL_PATH = ROOT / "models" / "resolute_random_forest.joblib"

LIVE_DIR = ROOT / "experiments" / "phase5" / "live_test"

ML_LOG = LIVE_DIR / "ml_detection_log.jsonl"

CSV_OUTPUT = ROOT / "experiments" / "phase5" / "windows_live_ml.csv"

KALI_IP = "192.168.56.101"
WINDOWS_IP = "192.168.56.1"

CAPTURE_DURATION = 60

LIVE_DIR.mkdir(parents=True, exist_ok=True)


# ============================================================
# 2. START RESOLUTE
# ============================================================

print("=" * 65)
print("RESOLUTE - WINDOWS LIVE ML DETECTION")
print("MODE: DRY RUN - NO FIREWALL ACTION")
print("=" * 65)


# ============================================================
# 3. LOAD RANDOM FOREST MODEL
# ============================================================

if not MODEL_PATH.exists():
    raise FileNotFoundError(
        f"Random Forest model not found: {MODEL_PATH}"
    )

model = joblib.load(MODEL_PATH)

print("\nRandom Forest loaded successfully.")

EXPECTED_FEATURES = len(model.feature_names_in_)

print("Expected features:", EXPECTED_FEATURES)


# ============================================================
# 4. SELECT WINDOWS HOST-ONLY INTERFACE
# ============================================================

try:
    interface = conf.ifaces.dev_from_index(10)

except Exception as error:
    raise RuntimeError(
        f"Could not select Windows network interface: {error}"
    )

print("Interface:", interface)


# ============================================================
# 5. INITIALIZE CICFLOWMETER
# ============================================================

session = FlowSession(
    output_mode="csv",
    output=str(CSV_OUTPUT),
    fields=None,
    verbose=False,
)

print("\nCICFlowMeter initialized successfully.")


# ============================================================
# 6. PREPARE A FRESH ML DETECTION LOG
# ============================================================

# Start this test with a clean log so old Ubuntu records
# are not mixed with current Windows detections.

with ML_LOG.open("w", encoding="utf-8"):
    pass

print("Fresh ML detection log created.")


# ============================================================
# 7. LIVE PACKET CAPTURE
# ============================================================

print("\n" + "=" * 65)

print(f"Capturing TCP traffic for {CAPTURE_DURATION} seconds...")

print("Kali IP   :", KALI_IP)
print("Windows IP:", WINDOWS_IP)

print("\nGenerate HTTP requests from Kali now.")

print("=" * 65)


try:

    sniff(
        iface=interface,
        filter=f"tcp and host {KALI_IP}",
        timeout=CAPTURE_DURATION,
        prn=session.process,
        store=False,
    )

except Exception as error:

    print("\nPacket capture error:", error)
    raise


print("\nPacket capture finished.")


# ============================================================
# 8. RETRIEVE FLOWS BEFORE FLUSHING
# ============================================================

print("\nRetrieving CICFlowMeter flows...")

# IMPORTANT:
# Retrieve the flows BEFORE calling flush_flows().
# Our diagnostic confirmed that flush_flows() clears
# the session's flow collection.

flows = list(session.get_flows())

print("Completed flows:", len(flows))


# ============================================================
# 9. MACHINE LEARNING DETECTION
# ============================================================

counts = {
    "BENIGN": 0,
    "ATTACK": 0,
    "ERROR": 0,
}

for number, flow in enumerate(flows, 1):

    try:

        # ----------------------------------------------------
        # Extract flow data
        # ----------------------------------------------------

        data = flow.get_data()

        # ----------------------------------------------------
        # Convert CICFlowMeter data into model features
        # ----------------------------------------------------

        features = adapt_cicflow_features(data)

        actual_features = features.shape[1]

        if actual_features != EXPECTED_FEATURES:
            raise ValueError(
                f"Expected {EXPECTED_FEATURES} features, "
                f"received {actual_features}"
            )

        # ----------------------------------------------------
        # Random Forest prediction
        # ----------------------------------------------------

        prediction = int(model.predict(features)[0])

        probabilities = model.predict_proba(features)[0]

        label = "ATTACK" if prediction == 1 else "BENIGN"

        confidence = float(max(probabilities))

        counts[label] += 1

        # ----------------------------------------------------
        # Prepare ML detection record
        # ----------------------------------------------------

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

            "probability_benign": float(probabilities[0]),

            "probability_attack": float(probabilities[1]),

            "feature_count": int(actual_features),

        }

        # ----------------------------------------------------
        # Save prediction to JSONL
        # ----------------------------------------------------

        with ML_LOG.open("a", encoding="utf-8") as log_file:

            log_file.write(
                json.dumps(result) + "\n"
            )

        # ----------------------------------------------------
        # Display detection result
        # ----------------------------------------------------

        print("\n" + "-" * 55)

        print("FLOW:", number)

        print("Source IP:", data.get("src_ip"))

        print("Source Port:", data.get("src_port"))

        print("Destination IP:", data.get("dst_ip"))

        print("Destination Port:", data.get("dst_port"))

        print("Protocol:", data.get("protocol"))

        print("Feature count:", actual_features)

        print("Prediction:", label)

        print("Confidence:", round(confidence, 4))

        print("Logged successfully.")

    except Exception as error:

        counts["ERROR"] += 1

        print("\nFlow:", number)

        print("Detection error:", error)


# ============================================================
# 10. FLUSH CICFLOWMETER AFTER PROCESSING
# ============================================================

print("\nFlushing CICFlowMeter session...")

session.flush_flows()

print("CICFlowMeter session flushed.")


# ============================================================
# 11. FINAL SUMMARY
# ============================================================

print("\n" + "=" * 65)

print("RESOLUTE LIVE ML DETECTION COMPLETED")

print("=" * 65)

print("Total flows processed :", len(flows))

print("BENIGN predictions    :", counts["BENIGN"])

print("ATTACK predictions    :", counts["ATTACK"])

print("Detection errors      :", counts["ERROR"])

print("\nML Detection Log:")
print(ML_LOG)

print("\nCSV Output:")
print(CSV_OUTPUT)

print("\nFirewall action: NONE")

print("=" * 65)