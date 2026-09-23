#!/usr/bin/env python3

import pandas as pd

from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import confusion_matrix


DATA_FILE = "detection/phase4/phase4_final_dataset.csv"


def main():
    print("==========================================")
    print(" Resolute - Phase 4 Error Analysis")
    print("==========================================\n")

    data = pd.read_csv(DATA_FILE)

    features = [
        "packets",
        "bytes",
        "packet_rate",
        "byte_rate",
        "avg_packet_size",
        "tcp_ratio",
        "udp_ratio",
        "icmp_ratio",
        "unique_dst_ips",
        "unique_dst_ports",
        "syn_count",
        "rst_count"
    ]

    X = data[features]
    y = data["label"]

    encoder = LabelEncoder()
    y_encoded = encoder.fit_transform(y)

    X_train, X_test, y_train, y_test, idx_train, idx_test = train_test_split(
        X,
        y_encoded,
        data.index,
        test_size=0.25,
        random_state=42,
        stratify=y_encoded
    )

    model = RandomForestClassifier(
        n_estimators=200,
        random_state=42,
        class_weight="balanced"
    )

    model.fit(X_train, y_train)

    predictions = model.predict(X_test)

    print("Class labels:")
    print(list(encoder.classes_))

    print("\n==========================================")
    print(" CONFUSION MATRIX")
    print("==========================================")

    cm = confusion_matrix(y_test, predictions)
    print(cm)

    print("\n==========================================")
    print(" MISCLASSIFIED SAMPLES")
    print("==========================================")

    errors = []

    for row_index, actual, predicted in zip(
        idx_test,
        y_test,
        predictions
    ):
        if actual != predicted:
            row = data.loc[row_index]

            errors.append({
                "dataset_index": row_index,
                "actual": encoder.inverse_transform([actual])[0],
                "predicted": encoder.inverse_transform([predicted])[0],
                "packets": row["packets"],
                "bytes": row["bytes"],
                "packet_rate": row["packet_rate"],
                "byte_rate": row["byte_rate"],
                "unique_dst_ports": row["unique_dst_ports"],
                "syn_count": row["syn_count"]
            })

    if errors:
        error_df = pd.DataFrame(errors)

        print(error_df.to_string(index=False))

        error_df.to_csv(
            "experiments/phase4/misclassified_samples.csv",
            index=False
        )

        print(
            "\nSaved misclassified samples to:"
            " experiments/phase4/misclassified_samples.csv"
        )

    else:
        print("No misclassified samples in the hold-out test set.")

    print("\n==========================================")
    print(" SECURITY INTERPRETATION")
    print("==========================================")

    false_positives = sum(
        (y_test == encoder.transform(["NORMAL"])[0]) &
        (predictions == encoder.transform(["SUSPICIOUS"])[0])
    )

    false_negatives = sum(
        (y_test == encoder.transform(["SUSPICIOUS"])[0]) &
        (predictions == encoder.transform(["NORMAL"])[0])
    )

    print(f"\nFalse Positives: {false_positives}")
    print(f"False Negatives: {false_negatives}")

    print("\nFalse Positive:")
    print("Normal traffic incorrectly classified as suspicious.")

    print("\nFalse Negative:")
    print("Suspicious traffic incorrectly classified as normal.")

    print("\n==========================================")
    print(" Analysis complete")
    print("==========================================")


if __name__ == "__main__":
    main()
