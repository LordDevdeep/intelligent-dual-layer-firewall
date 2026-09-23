#!/usr/bin/env python3

import pandas as pd

from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, StratifiedKFold, cross_val_score
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix
)


DATA_FILE = "detection/phase4/phase4_final_dataset.csv"


def main():

    print("==========================================")
    print(" Resolute - Phase 4 ML Evaluation")
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

    print(f"Dataset size: {len(data)}")
    print("\nClass distribution:")
    print(y.value_counts())
    print("\nFeatures:")
    print(", ".join(features))

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y_encoded,
        test_size=0.25,
        random_state=42,
        stratify=y_encoded
    )

    print("\nTrain samples:", len(X_train))
    print("Test samples:", len(X_test))

    model = RandomForestClassifier(
        n_estimators=200,
        random_state=42,
        class_weight="balanced"
    )

    model.fit(X_train, y_train)

    predictions = model.predict(X_test)

    print("\n==========================================")
    print(" HOLD-OUT TEST RESULTS")
    print("==========================================")

    print(f"\nAccuracy: {accuracy_score(y_test, predictions):.4f}\n")

    print("Classification Report:")
    print(
        classification_report(
            y_test,
            predictions,
            target_names=encoder.classes_,
            zero_division=0
        )
    )

    print("Confusion Matrix:")
    cm = confusion_matrix(y_test, predictions)

    print(cm)

    print("\nMatrix labels:")
    print(list(encoder.classes_))

    print("\n==========================================")
    print(" 5-FOLD CROSS-VALIDATION")
    print("==========================================")

    cv = StratifiedKFold(
        n_splits=5,
        shuffle=True,
        random_state=42
    )

    cv_scores = cross_val_score(
        model,
        X,
        y_encoded,
        cv=cv,
        scoring="f1_macro"
    )

    print("\nF1-macro scores:")
    print([round(score, 4) for score in cv_scores])

    print(f"\nMean F1-macro: {cv_scores.mean():.4f}")
    print(f"Std F1-macro:  {cv_scores.std():.4f}")

    print("\n==========================================")
    print(" FEATURE IMPORTANCE")
    print("==========================================")

    importance = pd.Series(
        model.feature_importances_,
        index=features
    ).sort_values(ascending=False)

    print(importance.round(4).to_string())


if __name__ == "__main__":
    main()
