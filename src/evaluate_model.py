#!/usr/bin/env python3

import os
import joblib
import pandas as pd

from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report,
    roc_auc_score
)


MODEL_PATH = "models/resolute_random_forest.joblib"
TEST_FILE = "datasets/cicids2017/ml/splits/test.parquet"


def main():

    print("=" * 70)
    print("RESOLUTE - FINAL TEST EVALUATION")
    print("=" * 70)

    print("\n[+] Loading model...")

    model = joblib.load(MODEL_PATH)

    print("[+] Model loaded successfully")

    print("\n[+] Loading test dataset...")

    df = pd.read_parquet(TEST_FILE)

    X_test = df.drop(
        columns=["Label", "Binary_Label"]
    )

    y_test = df["Binary_Label"]

    print(f"[+] Test samples: {len(y_test):,}")
    print(f"[+] Features: {X_test.shape[1]}")

    print("\n[+] Running predictions...")

    predictions = model.predict(X_test)

    probabilities = model.predict_proba(X_test)[:, 1]

    # Metrics
    accuracy = accuracy_score(
        y_test,
        predictions
    )

    precision = precision_score(
        y_test,
        predictions,
        zero_division=0
    )

    recall = recall_score(
        y_test,
        predictions,
        zero_division=0
    )

    f1 = f1_score(
        y_test,
        predictions,
        zero_division=0
    )

    auc = roc_auc_score(
        y_test,
        probabilities
    )

    print("\n" + "=" * 70)
    print("FINAL TEST RESULTS")
    print("=" * 70)

    print(f"Accuracy : {accuracy:.4f}")
    print(f"Precision: {precision:.4f}")
    print(f"Recall   : {recall:.4f}")
    print(f"F1-score : {f1:.4f}")
    print(f"ROC-AUC  : {auc:.4f}")

    print("\n" + "=" * 70)
    print("CONFUSION MATRIX")
    print("=" * 70)

    cm = confusion_matrix(
        y_test,
        predictions
    )

    print(cm)

    print("\nFormat:")
    print("[[True Negative, False Positive]")
    print(" [False Negative, True Positive]]")

    print("\n" + "=" * 70)
    print("CLASSIFICATION REPORT")
    print("=" * 70)

    print(
        classification_report(
            y_test,
            predictions,
            target_names=[
                "BENIGN",
                "ATTACK"
            ],
            zero_division=0
        )
    )


if __name__ == "__main__":
    main()
